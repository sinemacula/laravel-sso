<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Database;

use Illuminate\Database\Schema\Builder;

/**
 * Migration collision guard.
 *
 * Helper for the shipped migrations. Surfaces a clear error before any schema
 * mutation if the table a migration creates already exists, naming the
 * configuration key that renames it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MigrationCollisionGuard
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\Schema\Builder  $schema
     */
    public function __construct(

        /** Schema builder */
        private Builder $schema,
    ) {}

    /**
     * Throw if the table already exists. The configuration key is the one,
     * under `sso`, that names the table.
     *
     * @param  string  $table
     * @param  string  $configKey
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Database\TableAlreadyExistsException
     */
    public function ensureNotExists(string $table, string $configKey): void
    {
        if (!$this->schema->hasTable($table)) {
            return;
        }

        $connection = $this->schema->getConnection()->getName() ?? 'default';

        $message = sprintf(
            'Cannot install the laravel-sso migration for the \'%s\' table: a table with that name already exists on connection \'%s\'.'
            . ' Set `%s` in config/sso.php to a different name and re-run the migration.',
            $table,
            $connection,
            $configKey,
        );

        throw new TableAlreadyExistsException($message);
    }
}
