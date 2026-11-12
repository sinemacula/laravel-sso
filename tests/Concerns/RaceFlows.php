<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Connection;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;

/**
 * Races and rollback checks shared by the combined-flow tests. The first racer
 * commits only once the database shows another session waiting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RaceFlows
{
    use FailsDatabaseStatements, RacesProcesses;

    /** @var string The signal a racer raises once it holds its locks. */
    protected const string HOLDS = 'holds';

    /**
     * Start from fresh tables: rows a delete leaves until InnoDB's purge change
     * which session waits on which lock.
     *
     * @return bool
     */
    #[\Override]
    protected function reusesKeptTables(): bool
    {
        return false;
    }

    /**
     * The connection the package's tables live on.
     *
     * @return \Illuminate\Database\Connection
     */
    protected static function storageDatabase(): Connection
    {
        /** @var \Illuminate\Database\Connection */
        return DB::connection(StorageConnection::name());
    }

    /**
     * Open a `REPEATABLE READ` transaction and pin its snapshot with a read.
     *
     * @param  \Closure(): mixed  $reads
     * @return void
     *
     * @throws \LogicException
     */
    protected function openSnapshot(\Closure $reads): void
    {
        $database = self::storageDatabase();

        $database->statement(match ($database->getDriverName()) {
            'pgsql' => 'set session characteristics as transaction isolation level repeatable read',
            'mysql' => 'set session transaction isolation level repeatable read',
            default => throw new \LogicException(sprintf('No statement sets the isolation on [%s].', $database->getDriverName())),
        });

        $database->beginTransaction();

        $reads();
    }

    /**
     * What `race()` runs before its start: a snapshot for each racer named.
     *
     * @param  list<bool>  $reading
     * @param  \Closure(): mixed  $reads
     * @return \Closure(int): void
     */
    protected function snapshotsFor(array $reading, \Closure $reads): \Closure
    {
        return function (int $index) use ($reading, $reads): void {

            if (!($reading[$index] ?? false)) {
                return;
            }

            $this->openSnapshot($reads);
        };
    }

    /**
     * Commit the racer's snapshot, when it opened one.
     *
     * @return void
     */
    protected function commitSnapshot(): void
    {
        $database = self::storageDatabase();

        if ($database->transactionLevel() === 0) {
            return;
        }

        $database->commit();
    }

    /**
     * Do the work in a transaction and hold its locks until another session
     * waits on them, then commit.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $work
     * @return TResult
     *
     * @throws \Throwable
     */
    protected function holdThenCommit(\Closure $work): mixed
    {
        $result = self::storageDatabase()->transaction(function () use ($work): mixed {

            $result = $work();

            $this->holdUntilBlocked();

            return $result;
        });

        $this->commitSnapshot();

        return $result;
    }

    /**
     * Raise `HOLDS`, then wait until another session waits on this one.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    protected function holdUntilBlocked(): void
    {
        $this->signal(self::HOLDS);
        $this->awaitLockWaiter();
    }

    /**
     * Run the closure once, just before the commit that follows a statement
     * matching the pattern, while its locks are still held.
     *
     * @param  string  $pattern
     * @param  \Closure(): void  $paused
     * @return void
     */
    protected function pauseBeforeCommit(string $pattern, \Closure $paused): void
    {
        $name  = StorageConnection::resolvedName();
        $armed = false;
        $spent = false;

        DB::connection($name)->beforeExecuting(static function (string $query) use ($pattern, &$armed): void {
            $armed = $armed || preg_match($pattern, strtolower($query)) === 1;
        });

        Event::listen(TransactionCommitting::class, static function (TransactionCommitting $event) use ($name, $paused, &$armed, &$spent): void {

            if (!$armed || $spent || $event->connectionName !== $name) {
                return;
            }

            $spent = true;

            $paused();
        });
    }

    /**
     * Assert the racer succeeded or, in a snapshot on PostgreSQL, failed to
     * serialise, and answer whether it failed.
     *
     * @param  array{result: mixed, error: ?string}  $report
     * @param  bool  $inSnapshot
     * @return bool
     */
    protected static function assertRacerEnded(array $report, bool $inSnapshot): bool
    {
        if ($report['error'] !== self::RACE_SERIALIZATION_FAILURE) {
            Assert::assertNull($report['error'], 'A racer failed: ' . $report['error']);

            return false;
        }

        Assert::assertTrue($inSnapshot, 'A racer with no snapshot failed to serialise.');
        Assert::assertSame('pgsql', self::storageDatabase()->getDriverName(), 'A racer failed to serialise outside PostgreSQL.');

        return true;
    }

    /**
     * Arm the failure of the verb's statement on the table (a key under `sso.`
     * or a name), or of the commit when no verb is given.
     *
     * @param  ?string  $verb
     * @param  ?string  $table
     * @param  int  $occurrence
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    protected function armFailure(?string $verb, ?string $table, int $occurrence = 1): void
    {
        if ($verb === null) {
            $this->failCommit($occurrence);

            return;
        }

        $name = array_key_exists((string) $table, StorageConnection::TABLES) ? StorageConnection::table((string) $table) : (string) $table;

        $this->failStatement(self::onTable($verb, $name), $occurrence);
    }

    /**
     * Assert the work fails with the failure injected.
     *
     * @param  \Closure(): mixed  $work
     * @return void
     */
    protected static function assertInjectedFailure(\Closure $work): void
    {
        try {
            $work();

            Assert::fail('The work went on.');
        } catch (QueryException $exception) {
            Assert::assertTrue(self::isInjectedFailure($exception));
        }
    }

    /**
     * Allow every attempt, so no racer's transaction holds the counters locked.
     *
     * @return void
     */
    protected function allowEveryAttempt(): void
    {
        $this->app?->instance(AttemptLimiter::class, new readonly class implements AttemptLimiter {
            /**
             * Allow the attempt.
             *
             * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject  $subject
             * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptResult
             */
            #[\Override]
            public function attempt(AttemptSubject $subject): AttemptResult
            {
                unset($subject);

                return AttemptResult::allowed();
            }
        });
    }

    /**
     * Every row of the package's tables and those named, in a stable order.
     *
     * @param  list<string>  $also
     * @return array<string, list<string>>
     *
     * @throws \InvalidArgumentException
     */
    protected static function storedRows(array $also = []): array
    {
        $database = self::storageDatabase();
        $schema   = $database->getSchemaBuilder();
        $tables   = [...array_map(StorageConnection::table(...), array_keys(StorageConnection::TABLES)), ...$also];
        $stored   = [];

        foreach ($tables as $table) {

            if (!$schema->hasTable($table)) {
                continue;
            }

            $rows = array_map(self::comparableRow(...), $database->table($table)->get()->all());

            sort($rows);

            $stored[$table] = array_values($rows);
        }

        return $stored;
    }

    /**
     * Wait until another session waits on a lock this one holds. MySQL's holder
     * is found by transaction: when a waiter makes a prune's implicit index
     * lock explicit, `BLOCKING_THREAD_ID` names the waiter.
     *
     * @return void
     *
     * @throws \RuntimeException
     * @throws \LogicException
     */
    private function awaitLockWaiter(): void
    {
        $database = self::storageDatabase();
        $query    = match ($database->getDriverName()) {
            'pgsql' => 'select count(*) as waiting from (select distinct pid from pg_locks where not granted) as waits where pg_backend_pid() = any(pg_blocking_pids(waits.pid))',
            'mysql' => 'select count(*) as waiting from performance_schema.data_lock_waits as waits '
                . 'join information_schema.innodb_trx as holder on holder.trx_id = waits.BLOCKING_ENGINE_TRANSACTION_ID '
                . 'where holder.trx_mysql_thread_id = connection_id()',
            default => throw new \LogicException(sprintf('No query finds the sessions waiting on a lock on [%s].', $database->getDriverName())),
        };
        $deadline = microtime(true) + self::RACE_DEADLINE_SECONDS;

        do {

            $row = $database->selectOne($query, [], false);

            if ($row instanceof \stdClass && (int) ($row->waiting ?? 0) > 0) {
                return;
            }

            usleep(5000);
        } while (microtime(true) < $deadline);

        throw new \RuntimeException('No session came to wait on the locks held.');
    }

    /**
     * The row, comparable; PostgreSQL reads a binary column as a stream.
     *
     * @param  object  $row
     * @return string
     */
    private static function comparableRow(object $row): string
    {
        $values = array_map(static fn (mixed $value): mixed => is_resource($value) ? stream_get_contents($value) : $value, (array) $row);

        ksort($values);

        return serialize($values);
    }
}
