<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Connection;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Makes a named database statement, or a commit, fail as a real one does, on
 * any step of a flow and not only its first lookup (SSO-11.4). The statement is
 * never sent; a `QueryException` naming SQLSTATE `HY000` is thrown in its
 * place, with a message a test can tell apart. Nothing else about the
 * connection changes, so whatever a flow does next it does for real, and a
 * transaction the failure unwinds really rolls back.
 *
 * `failStatement()` takes a regular expression, tried on the statement in lower
 * case, with the occurrence to fail at: `onTable()` builds one from a verb and
 * a table through the connection's grammar, so it works on every engine.
 * Whatever was armed is disarmed by the failure, so a retry or the next step
 * runs. `failCommit()` fails the outermost commit on the connection instead,
 * rolling the transaction back in the database first, as a failed commit leaves
 * it.
 *
 * Each call arms one failure; `disarmDatabaseFailures()` drops any not yet
 * reached, and `databaseFailuresFired()` says how many fired, so a test can
 * show the step it meant to fail was reached.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait FailsDatabaseStatements
{
    /** @var string The driver's message on an injected failure. */
    protected const string INJECTED_FAILURE = 'injected database failure';

    /** @var ?\ArrayObject<string, mixed> What is armed, shared with the callbacks the connections hold. */
    private ?\ArrayObject $databaseFailures = null;

    /** @var array<string, true> The connections a statement hook is installed on. */
    private array $failingConnections = [];

    /**
     * Fail the occurrence of the statement matching the pattern on the
     * connection, the storage connection unless another is named.
     *
     * @param  string  $pattern
     * @param  int  $occurrence
     * @param  ?string  $connection
     * @return void
     */
    protected function failStatement(string $pattern, int $occurrence = 1, ?string $connection = null): void
    {
        $name = $connection ?? StorageConnection::resolvedName();

        $this->databaseFailureState()['statements'][] = ['pattern' => $pattern, 'left' => $occurrence, 'connection' => $name];

        $this->installStatementHook($name);
    }

    /**
     * Make the next statements matching the pattern fail as the database does
     * when it rolls one back as a deadlock, the given number of times: a
     * transaction that retries such failures is tried again.
     *
     * @param  string  $pattern
     * @param  int  $times
     * @param  ?string  $connection
     * @return void
     */
    protected function deadlockStatement(string $pattern, int $times = 1, ?string $connection = null): void
    {
        $name = $connection ?? StorageConnection::resolvedName();

        for ($time = 0; $time < $times; $time++) {
            $this->databaseFailureState()['statements'][] = ['pattern' => $pattern, 'left' => 1, 'connection' => $name, 'deadlock' => true];
        }

        $this->installStatementHook($name);
    }

    /**
     * Fail the occurrence of the outermost commit on the connection, the
     * storage connection unless another is named.
     *
     * @param  int  $occurrence
     * @param  ?string  $connection
     * @return void
     */
    protected function failCommit(int $occurrence = 1, ?string $connection = null): void
    {
        $name   = $connection ?? StorageConnection::resolvedName();
        $failed = false;

        Event::listen(TransactionCommitting::class, function (TransactionCommitting $event) use ($name, &$occurrence, &$failed): void {

            if ($failed || $event->connectionName !== $name || --$occurrence > 0) {
                return;
            }

            $failed = true;

            $this->databaseFailureState()['fired']++;

            $event->connection->getPdo()->rollBack();

            throw self::injectedFailure($event->connection, 'commit');
        });
    }

    /**
     * A pattern matching a statement of the verb on the table, through the
     * connection's grammar.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  ?string  $connection
     * @return string
     */
    protected static function onTable(string $verb, string $table, ?string $connection = null): string
    {
        $wrapped = DB::connection($connection ?? StorageConnection::name())->getQueryGrammar()->wrapTable($table);

        return '/^\s*' . preg_quote($verb, '/') . '\b.*' . preg_quote(strtolower($wrapped), '/') . '/s';
    }

    /**
     * How many injected failures have fired.
     *
     * @return int
     */
    protected function databaseFailuresFired(): int
    {
        return $this->databaseFailureState()['fired'];
    }

    /**
     * Drop every failure not yet reached.
     *
     * @return void
     */
    protected function disarmDatabaseFailures(): void
    {
        $this->databaseFailureState()['statements'] = [];
    }

    /**
     * Whether an exception is, or was caused by, an injected failure.
     *
     * @param  ?\Throwable  $exception
     * @return bool
     */
    protected static function isInjectedFailure(?\Throwable $exception): bool
    {
        for ($current = $exception; $current !== null; $current = $current->getPrevious()) {
            if (str_contains($current->getMessage(), self::INJECTED_FAILURE)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The state shared with the hooks.
     *
     * @return \ArrayObject<string, mixed>
     */
    private function databaseFailureState(): \ArrayObject
    {
        return $this->databaseFailures ??= new \ArrayObject(['statements' => [], 'fired' => 0]);
    }

    /**
     * Install the hook that throws in place of an armed statement, once on each
     * connection.
     *
     * @param  string  $name
     * @return void
     */
    private function installStatementHook(string $name): void
    {
        if (isset($this->failingConnections[$name])) {
            return;
        }

        $this->failingConnections[$name] = true;

        $state = $this->databaseFailureState();

        DB::connection($name)->beforeExecuting(static function (string $query, array $bindings, Connection $connection) use ($state, $name): void {

            unset($bindings);

            $statements = $state['statements'];

            foreach ($statements as $index => $armed) {

                if ($armed['connection'] !== $name || preg_match($armed['pattern'], strtolower($query)) !== 1) {
                    continue;
                }

                $statements[$index]['left']--;

                if ($statements[$index]['left'] > 0) {
                    $state['statements'] = $statements;

                    return;
                }

                unset($statements[$index]);

                $state['statements'] = array_values($statements);
                $state['fired']++;

                throw self::injectedFailure($connection, $query, $armed['deadlock'] ?? false);
            }
        });
    }

    /**
     * The exception a failed statement raises.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $query
     * @param  bool  $deadlock
     * @return \Illuminate\Database\QueryException
     */
    private static function injectedFailure(Connection $connection, string $query, bool $deadlock = false): QueryException
    {
        $driver            = new \PDOException(($deadlock ? 'Deadlock found when trying to get lock: ' : '') . self::INJECTED_FAILURE);
        $driver->errorInfo = ['HY000', 1, self::INJECTED_FAILURE];

        return new QueryException((string) $connection->getName(), $query, [], $driver);
    }
}
