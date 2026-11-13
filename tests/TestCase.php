<?php

declare(strict_types = 1);

namespace Tests;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as OrchestraTestCase;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * Base test case: the package in Testbench, on the database `DB_CONNECTION`
 * names (in-memory SQLite when unset).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class TestCase extends OrchestraTestCase
{
    /** @var string The connection each test runs on, in its worker's database. */
    private const string CONNECTION = 'testing';

    /** @var string The package's shipped migrations. */
    private const string MIGRATIONS = __DIR__ . '/../database/migrations';

    /** @var array<string, true> Worker databases this process has created. */
    private static array $workerDatabases = [];

    /** @var array{key: string, connection: array<string, mixed>, tables: list<string>, schema: string} The tables this process keeps migrated, and how. */
    private static array $keptTables = ['key' => '', 'connection' => [], 'tables' => [], 'schema' => ''];

    /** @var bool Whether this test has its package tables already. */
    private bool $hasPackageTables = false;

    /**
     * Destroy the application, then close its database connections, which would
     * otherwise stay open until its reference cycles are collected.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        /** @var ?\Illuminate\Database\DatabaseManager $database */
        $database = $this->app?->make('db');

        parent::tearDown();

        foreach ($database?->getConnections() ?? [] as $connection) {
            $connection->disconnect();
        }

        gc_collect_cycles();
    }

    /**
     * Give the test every shipped table, empty, as the settings place them. On
     * a server, tables on the worker's connection are kept between tests and
     * emptied while their schema still matches the migrations.
     *
     * @return void
     */
    protected function usePackageTables(): void
    {
        if ($this->hasPackageTables) {
            return;
        }

        $this->hasPackageTables = true;

        $migrations = $this->packageMigrations();
        $connection = app(ConfigRepository::class)->array('database.connections.' . self::CONNECTION);

        if ($connection['driver'] === 'sqlite') {
            $this->migrate($migrations);

            return;
        }

        $tables = $this->packageTables($migrations);
        $names  = array_column($tables, 1);
        $kept   = array_unique(array_column($tables, 0)) === [self::CONNECTION] && !str_contains(implode(',', $names), '.');
        $key    = serialize([$names, $connection]);

        if ($kept && $this->reusesKeptTables() && self::$keptTables['key'] === $key && self::$keptTables['schema'] === $this->schemaOf($names)) {
            foreach (array_reverse($names) as $table) {
                DB::connection(self::CONNECTION)->table($table)->delete();
            }

            return;
        }

        $this->dropKeptTables();
        $this->dropTables($tables);
        $this->migrate($migrations);

        if (!$kept) {
            $this->beforeApplicationDestroyed(fn () => $this->dropTables(array_reverse($tables)));

            return;
        }

        self::$keptTables = ['key' => $key, 'connection' => $connection, 'tables' => $names, 'schema' => $this->schemaOf($names)];
    }

    /**
     * Whether the test may start from emptied kept tables. Deleted rows stay in
     * InnoDB's indexes until purged, which changes who waits on a row lock.
     *
     * @return bool
     */
    protected function reusesKeptTables(): bool
    {
        return true;
    }

    /**
     * Drop the tables kept on the worker's database, for a test that builds its
     * own schema.
     *
     * @return void
     */
    protected function dropKeptTables(): void
    {
        if (self::$keptTables['tables'] === []) {
            return;
        }

        /** @var \Illuminate\Database\Connection $connection */
        $connection = DB::build(self::$keptTables['connection']);
        $schema     = $connection->getSchemaBuilder();

        foreach (array_reverse(self::$keptTables['tables']) as $table) {
            $schema->dropIfExists($table);
        }

        $connection->disconnect();

        self::$keptTables = ['key' => '', 'connection' => [], 'tables' => [], 'schema' => ''];
    }

    /**
     * Register the package service provider.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [
            SsoServiceProvider::class,
        ];
    }

    /**
     * Configure the `DB_CONNECTION` database, in-memory SQLite if unset.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('app.key', 'base64:' . base64_encode('laravel-sso test key of 32 bytes'));
        $config->set('database.default', self::CONNECTION);
        $config->set('database.connections.' . self::CONNECTION, $this->databaseConnection());
    }

    /**
     * Run the change once, as the next transaction on the storage connection
     * begins: between a helper's first read and its locks.
     *
     * @param  \Closure(): mixed  $change
     * @return void
     */
    protected function beforeTheNextTransaction(\Closure $change): void
    {
        $pending = $change;

        DB::connection(StorageConnection::name())->beforeStartingTransaction(static function () use (&$pending): void {

            $run     = $pending;
            $pending = null;

            $run?->__invoke();
        });
    }

    /**
     * Each shipped migration in order, keyed by its table's `sso.` setting.
     *
     * @return array<string, \Illuminate\Database\Migrations\Migration>
     */
    private function packageMigrations(): array
    {
        $files = glob(self::MIGRATIONS . '/*.php') ?: [];

        sort($files);

        $migrations = [];

        foreach ($files as $file) {
            preg_match('/create_(sso_\w+)_table\.php$/', $file, $table);

            $key = array_search($table[1] ?? '', StorageConnection::TABLES, true);

            assert(is_string($key), "{$file} creates no package table.");

            $migration = require $file;

            assert($migration instanceof Migration);

            $migrations[$key] = $migration;
        }

        return $migrations;
    }

    /**
     * Run each migration up, in order.
     *
     * @param  array<string, \Illuminate\Database\Migrations\Migration>  $migrations
     * @return void
     */
    private function migrate(array $migrations): void
    {
        foreach ($migrations as $migration) {
            $migration->up(); // @phpstan-ignore method.notFound
        }
    }

    /**
     * Each package table, in migration order, with its connection.
     *
     * @param  array<string, \Illuminate\Database\Migrations\Migration>  $migrations
     * @return list<array{0: string, 1: string}>
     */
    private function packageTables(array $migrations): array
    {
        $default = app(ConfigRepository::class)->string('database.default');
        $tables  = [];

        foreach ($migrations as $key => $migration) {
            $tables[] = [$migration->getConnection() ?? $default, StorageConnection::table($key)];
        }

        return $tables;
    }

    /**
     * Describe the tables as the database reports them, so any schema change
     * yields a different description.
     *
     * @param  list<string>  $tables
     * @return string
     */
    private function schemaOf(array $tables): string
    {
        $connection = DB::connection(self::CONNECTION);
        $tables     = array_map(static fn (string $table): string => $connection->getTablePrefix() . $table, $tables);
        $in         = implode(', ', array_fill(0, count($tables), '?'));

        return serialize(array_map(static fn (string $query): array => $connection->select($query, $tables), $this->schemaQueries($connection->getDriverName(), $in)));
    }

    /**
     * The queries that describe the tables; PostgreSQL's catalogue answers far
     * faster than its `information_schema` views.
     *
     * @param  string  $driver
     * @param  string  $in
     * @return list<string>
     */
    private function schemaQueries(string $driver, string $in): array
    {
        if ($driver === 'pgsql') {
            return [
                'select relname, relkind, relpersistence, reloptions from pg_class'
                    . " where relnamespace = current_schema()::regnamespace and relname in ({$in}) order by 1",
                'select c.relname, a.attnum, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull, a.attcollation,'
                    . ' pg_get_expr(d.adbin, d.adrelid) from pg_attribute a join pg_class c on c.oid = a.attrelid'
                    . ' left join pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum'
                    . " where c.relnamespace = current_schema()::regnamespace and c.relname in ({$in})"
                    . ' and a.attnum > 0 and not a.attisdropped order by 1, 2',
                'select tablename, indexname, indexdef from pg_indexes'
                    . " where schemaname = current_schema() and tablename in ({$in}) order by 1, 2",
                'select c.relname, con.conname, con.contype, pg_get_constraintdef(con.oid) from pg_constraint con'
                    . ' join pg_class c on c.oid = con.conrelid'
                    . " where c.relnamespace = current_schema()::regnamespace and c.relname in ({$in}) order by 1, 2",
                'select c.relname, t.tgname, t.tgenabled, pg_get_triggerdef(t.oid) from pg_trigger t'
                    . ' join pg_class c on c.oid = t.tgrelid'
                    . " where c.relnamespace = current_schema()::regnamespace and c.relname in ({$in}) and not t.tgisinternal order by 1, 2",
            ];
        }

        return [
            'select table_name, engine, table_collation, create_options from information_schema.tables'
                . " where table_schema = database() and table_name in ({$in}) order by 1",
            "select * from information_schema.columns where table_schema = database() and table_name in ({$in})"
                . ' order by table_name, ordinal_position',
            'select table_name, index_name, non_unique, seq_in_index, column_name, sub_part, index_type, collation, is_visible, expression'
                . ' from information_schema.statistics'
                . " where table_schema = database() and table_name in ({$in}) order by 1, 2, 4",
            'select table_name, constraint_name, constraint_type from information_schema.table_constraints'
                . " where table_schema = database() and table_name in ({$in}) order by 1, 2",
            'select event_object_table, trigger_name, event_manipulation, action_timing, action_statement from information_schema.triggers'
                . " where trigger_schema = database() and event_object_table in ({$in}) order by 1, 2",
        ];
    }

    /**
     * Drop each table on its connection, where the test still configures it.
     *
     * @param  list<array{0: string, 1: string}>  $tables
     * @return void
     */
    private function dropTables(array $tables): void
    {
        $config = app(ConfigRepository::class);

        foreach ($tables as [$connection, $table]) {
            if (!$config->has('database.connections.' . $connection)) {
                continue;
            }

            Schema::connection($connection)->dropIfExists($table);
        }
    }

    /**
     * Build the database connection config from environment variables.
     *
     * @return array<string, mixed>
     */
    private function databaseConnection(): array
    {
        $driver = getenv('DB_CONNECTION') ?: 'sqlite';

        if ($driver === 'sqlite') {
            return [
                'driver'   => 'sqlite',
                'database' => ':memory:',
                'prefix'   => '',
            ];
        }

        $connection = [
            'driver'    => $driver,
            'host'      => getenv('DB_HOST') ?: '127.0.0.1',
            'port'      => getenv('DB_PORT') ?: $this->defaultPort($driver),
            'database'  => getenv('DB_DATABASE') ?: 'laravel_sso_test',
            'username'  => getenv('DB_USERNAME') ?: 'root',
            'password'  => getenv('DB_PASSWORD') ?: '',
            'prefix'    => '',
            'charset'   => $driver === 'pgsql' ? 'utf8' : 'utf8mb4',
            'collation' => $driver === 'pgsql' ? null : 'utf8mb4_unicode_ci',
        ];

        $connection['database'] = $this->workerDatabase($connection);

        return $connection;
    }

    /**
     * The database this process tests against: its own, named after paratest's
     * `TEST_TOKEN` and created afresh on first use, so workers never collide.
     *
     * @param  array{driver: string, host: string, port: string, database: string, username: string, password: string}  $connection
     * @return string
     */
    private function workerDatabase(array $connection): string
    {
        $token    = getenv('TEST_TOKEN');
        $database = $connection['database'] . '_' . ($token === false || $token === '' ? '0' : $token);

        if (isset(self::$workerDatabases[$database])) {
            return $database;
        }

        $dsn = sprintf('%s:host=%s;port=%s;dbname=%s', $connection['driver'], $connection['host'], $connection['port'], $connection['database']);
        $pdo = new \PDO($dsn, $connection['username'], $connection['password']);

        $quoted = $connection['driver'] === 'pgsql' ? '"' . $database . '"' : '`' . $database . '`';

        $pdo->exec('DROP DATABASE IF EXISTS ' . $quoted . ($connection['driver'] === 'pgsql' ? ' WITH (FORCE)' : ''));
        $pdo->exec('CREATE DATABASE ' . $quoted);

        self::$workerDatabases[$database] = true;

        return $database;
    }

    /**
     * Return the default database port for the given driver.
     *
     * @param  string  $driver
     * @return string
     */
    private function defaultPort(string $driver): string
    {
        return $driver === 'pgsql' ? '5432' : '3306';
    }
}
