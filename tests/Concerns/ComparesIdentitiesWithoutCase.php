<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Models\Link;

/**
 * Gives a test a case-insensitive identity collation, as MySQL's default is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait ComparesIdentitiesWithoutCase
{
    /**
     * Make the links table match identity ids without case; skipped on
     * PostgreSQL, whose comparisons are exact.
     *
     * @return void
     */
    protected function compareIdentityIdsWithoutCase(): void
    {
        $name     = StorageConnection::name();
        $database = DB::connection($name);
        $table    = (new Link)->getTable();

        if ($database->getDriverName() === 'pgsql') {
            static::markTestSkipped('PostgreSQL compares an identity exactly, whatever the package does after.');
        }

        if ($database->getDriverName() !== 'sqlite') {
            return;
        }

        foreach (Schema::connection($name)->getIndexes($table) as $index) {

            if (!in_array('identity_id', $index['columns'], true)) {
                continue;
            }

            $database->statement('DROP INDEX "' . $index['name'] . '"');
        }

        $database->statement('ALTER TABLE "' . $table . '" DROP COLUMN "identity_id"');
        $database->statement('ALTER TABLE "' . $table . '" ADD COLUMN "identity_id" varchar NOT NULL DEFAULT \'\' COLLATE NOCASE');
    }
}
