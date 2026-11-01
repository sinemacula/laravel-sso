<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Migrations\Migration;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Creates and drops the connections table and the keys and certificates table
 * through their shipped migrations, on the storage connection and under their
 * configured names, and makes connections for a test to work on.
 *
 * A test calls `createConnectionTables()` in its `setUp()` and
 * `dropConnectionTables()` in its `tearDown()`, before the parent's, so a
 * persistent database starts the next test without them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait UsesConnections
{
    /** @var list<string> The shipped migrations of the two tables, in the order they run. */
    private static array $connectionMigrations = [
        '2026_11_01_000000_create_sso_connections_table.php',
        '2026_11_01_000001_create_sso_keys_table.php',
    ];

    /**
     * Run the two tables' shipped migrations.
     *
     * @return void
     */
    protected function createConnectionTables(): void
    {
        foreach (self::$connectionMigrations as $migration) {
            self::connectionMigration($migration)->up(); // @phpstan-ignore method.notFound
        }
    }

    /**
     * Roll the two tables' shipped migrations back.
     *
     * @return void
     */
    protected function dropConnectionTables(): void
    {
        foreach (array_reverse(self::$connectionMigrations) as $migration) {
            self::connectionMigration($migration)->down(); // @phpstan-ignore method.notFound
        }
    }

    /**
     * Make and save a connection: an OIDC connection of `tenant-1` named
     * `Example`, disabled, with no settings or mapping, unless the attributes
     * given say otherwise.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    protected function makeConnection(array $attributes = []): Connection
    {
        $connection = new Connection;

        $connection->forceFill($attributes + [
            'tenant_id'    => 'tenant-1',
            'protocol'     => 'oidc',
            'display_name' => 'Example',
        ])->save();

        return $connection;
    }

    /**
     * The shipped migration of the name.
     *
     * @param  string  $name
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function connectionMigration(string $name): Migration
    {
        return require dirname(__DIR__, 2) . '/database/migrations/' . $name;
    }
}
