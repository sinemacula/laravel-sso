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
 * What the combined-flow tests share (SSO-4.5, SSO-8.8, SSO-9.9, SSO-10.5): how
 * a race establishes the order it claims, and how a rollback test reads what is
 * stored.
 *
 * A racer that goes first holds its locks in a transaction, raises `HOLDS`, and
 * then waits until the database itself shows another session waiting on what it
 * holds, so the overlap is real and never a matter of timing; only then does it
 * commit. That wait fails loudly at the deadline. Where the first racer cannot
 * hold a transaction open itself, as `Pruning\Pruner` and a completion cannot,
 * `pauseBeforeCommit()` does the same from inside its transaction, on the
 * commit that follows the statement named.
 *
 * A racer given a snapshot opens a `REPEATABLE READ` transaction before the
 * race begins and reads in it, as a caller does, so a re-read that decides a
 * write must be a locking one on MySQL, and on PostgreSQL such a racer fails to
 * serialise when what it locks changed since, which is a safe end there alone.
 *
 * `storedRows()` reads every row of the package's tables, and of those named,
 * so a rollback test compares what stood before with what stands after, whole,
 * once `armFailure()` has failed the statement or the commit it names.
 *
 * A race starts from the package's tables migrated afresh, never from those an
 * earlier test kept (`reusesKeptTables()`): the rows a delete leaves in
 * InnoDB's indexes until its purge removes them change which session waits on
 * which lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RaceFlows
{
    use FailsDatabaseStatements, RacesProcesses;

    /** @var string The signal a racer raises once it holds what the other must find held. */
    protected const string HOLDS = 'holds';

    /**
     * Start from tables migrated afresh, since the rows a delete leaves until
     * InnoDB's purge removes them change which session waits on which lock.
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
     * Open a transaction at `REPEATABLE READ` and read in it, which pins its
     * snapshot.
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
     * What `race()` runs before its start: a snapshot opened by each racer told
     * to, by its index.
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
     * Do the work in a transaction, a savepoint inside a snapshot; hold what it
     * locked until another session waits on it; then commit, the snapshot too.
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
     * Raise `HOLDS`, then wait until another session waits on a lock this one
     * holds.
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
     * Run the closure once, in the transaction's last moment before the commit
     * that follows a statement matching the pattern, whose locks it still
     * holds.
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
     * Assert the racer ended without an error, or failed to serialise, which is
     * accepted only inside a snapshot on PostgreSQL, and answer whether it did.
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
     * Arm the failure: of the occurrence of the verb's statement on the table,
     * named by its key under `sso.` or itself, or of the commit when no verb is
     * given.
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
     * Allow every attempt, whose counters a racer's transaction would otherwise
     * hold locked.
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
     * Every row of the package's tables that exist and of the tables named,
     * each in a form that compares whole and in no order the database chose.
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
     * Wait until another session waits on a lock this one holds, failing loudly
     * at the deadline. MySQL finds the holder by its transaction: where a
     * delete left only an implicit lock on a secondary index, as a prune does,
     * the waiter makes it explicit, and `BLOCKING_THREAD_ID` then names the
     * waiter.
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
     * The row in a form that compares whole: a binary column reads as a stream
     * on PostgreSQL.
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
