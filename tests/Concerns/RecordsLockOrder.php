<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Records the locks taken on the storage connection, in order. SQLite has no
 * locking read, so a lock for update compiles to a marker comment.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RecordsLockOrder
{
    /** @var ?\ArrayObject<int, array{sql: string, bindings: array<int, mixed>}> Every statement run since recording began. */
    private ?\ArrayObject $recordedStatements = null;

    /**
     * Start recording the statements run on the storage connection.
     *
     * @return void
     */
    protected function recordLockOrder(): void
    {
        $database = DB::connection(StorageConnection::name());

        if ($database->getDriverName() === 'sqlite') {
            $database->setQueryGrammar(new class ($database) extends SQLiteGrammar {
                /**
                 * Compile a lock for update to a marker comment.
                 *
                 * @param  \Illuminate\Database\Query\Builder  $query
                 * @param  bool|string  $value
                 * @return string
                 */
                #[\Override]
                protected function compileLock(Builder $query, $value): string
                {
                    return $value === true ? ' /* for update */' : '';
                }
            });
        }

        /** @var \ArrayObject<int, array{sql: string, bindings: array<int, mixed>}> $statements */
        $statements = new \ArrayObject;

        $this->recordedStatements = $statements;

        $database->listen(static function (QueryExecuted $query) use ($statements): void {
            $statements[] = ['sql' => strtolower($query->sql), 'bindings' => array_values($query->bindings)];
        });
    }

    /**
     * The locks taken since recording began, in order.
     *
     * @return list<string>
     */
    protected function lockOrder(): array
    {
        $locks = [];

        foreach ($this->recordedStatements ?? [] as $statement) {

            $lock = self::lockOf($statement['sql'], $statement['bindings']);

            if ($lock === null) {
                continue;
            }

            $locks[] = $lock;
        }

        return $locks;
    }

    /**
     * How many recorded statements name the enforcement table.
     *
     * @return int
     */
    protected function enforcementStatements(): int
    {
        $table = StorageConnection::table('enforcement.table');

        $statements = $this->recordedStatements?->getArrayCopy() ?? [];

        return count(array_filter($statements, static fn (array $statement): bool => self::tableOf($statement['sql']) === $table));
    }

    /**
     * The lock the statement takes, or `null` when it takes none.
     *
     * @param  string  $sql
     * @param  array<int, mixed>  $bindings
     * @return ?string
     */
    private static function lockOf(string $sql, array $bindings): ?string
    {
        $table = self::tableOf($sql);

        if (str_starts_with($sql, 'insert')) {
            return self::upsertOf($table);
        }

        if (!str_contains($sql, 'for update')) {
            return null;
        }

        return match ($table) {
            StorageConnection::table('enforcement.table')            => 'enforcement',
            StorageConnection::table('connections.table')            => 'connections ' . implode(', ', array_filter($bindings, is_string(...))),
            StorageConnection::table('handoff_codes.table')          => 'code',
            StorageConnection::table('authorization_requests.table') => 'request',
            StorageConnection::table('links.table')                  => 'link',
            StorageConnection::table('identity_guards.table')        => 'identity mark',
            default                                                  => (string) $table,
        };
    }

    /**
     * The lock an upsert into the table takes, or `null` for any other table.
     *
     * @param  ?string  $table
     * @return ?string
     */
    private static function upsertOf(?string $table): ?string
    {
        return match ($table) {
            StorageConnection::table('enforcement.table')     => 'enforcement upsert',
            StorageConnection::table('identity_guards.table') => 'identity guard',
            default                                           => null,
        };
    }

    /**
     * The table the statement reads or writes first, unquoted.
     *
     * @param  string  $sql
     * @return ?string
     */
    private static function tableOf(string $sql): ?string
    {
        return preg_match('/\b(?:from|into|update)\s+["`]?([a-z0-9_]+)["`]?/', $sql, $matches) === 1 ? $matches[1] : null;
    }
}
