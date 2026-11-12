<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\Facades\DB;

/**
 * Builds a split SQLite connection whose replica never catches up, with sticky
 * reads off, so only `useWritePdo()` reaches the primary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithLaggingReplica
{
    /** @var string Connection that reads from the replica and writes to the primary. */
    protected const string SPLIT_CONNECTION = 'split';

    /** @var string Direct connection to the replica file. */
    protected const string REPLICA_CONNECTION = 'replica';

    /** @var string Direct connection to the primary file. */
    protected const string PRIMARY_CONNECTION = 'primary';

    /** @var string A second split connection, for the counters on a connection of their own. */
    protected const string COUNTERS_CONNECTION = 'counters_split';

    /** @var string Direct connection to the counters' replica file. */
    protected const string COUNTERS_REPLICA_CONNECTION = 'counters_replica';

    /** @var string Direct connection to the counters' primary file. */
    protected const string COUNTERS_PRIMARY_CONNECTION = 'counters_primary';

    /** @var list<string> The storage connection's shipped migrations, in order. */
    private static array $replicaMigrations = [
        '2026_10_31_000000_create_sso_single_use_keys_table.php',
        '2026_11_01_000000_create_sso_connections_table.php',
        '2026_11_01_000001_create_sso_keys_table.php',
        '2026_11_02_000000_create_sso_domains_table.php',
        '2026_11_02_000001_create_sso_enforcement_table.php',
        '2026_11_03_000000_create_sso_links_table.php',
        '2026_11_03_000001_create_sso_authorization_requests_table.php',
        '2026_11_03_000002_create_sso_handoff_codes_table.php',
        '2026_11_03_000003_create_sso_identity_guards_table.php',
    ];

    /** @var array<int, string> Temporary SQLite files created for this test. */
    private array $laggingReplicaFiles = [];

    /**
     * Register the primary, replica and default split connections.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    protected function configureLaggingReplica(ConfigRepository $config): void
    {
        $this->registerLaggingConnection($config, self::SPLIT_CONNECTION, self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION);

        $config->set('database.default', self::SPLIT_CONNECTION);
    }

    /**
     * Register a second lagging pair for the rate limit counters.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    protected function configureLaggingCounters(ConfigRepository $config): void
    {
        $this->registerLaggingConnection($config, self::COUNTERS_CONNECTION, self::COUNTERS_PRIMARY_CONNECTION, self::COUNTERS_REPLICA_CONNECTION);

        $config->set('sso.rate_limits.connection', self::COUNTERS_CONNECTION);
    }

    /**
     * Run the shipped migrations on every primary and replica.
     *
     * @return void
     */
    protected function migrateSsoTablesOnPrimaryAndReplica(): void
    {
        /** @var \Illuminate\Database\DatabaseManager $manager */
        $manager  = app(DatabaseManager::class);
        $counters = config('sso.rate_limits.connection');

        foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {

            $manager->setDefaultConnection($connection);

            config()->set('sso.rate_limits.connection');

            foreach ([...self::$replicaMigrations, ...($counters === null ? ['2026_10_31_000001_create_sso_rate_limits_table.php'] : [])] as $file) {
                self::replicaMigration($file)->up(); // @phpstan-ignore method.notFound
            }
        }

        if ($counters !== null) {
            foreach ([self::COUNTERS_PRIMARY_CONNECTION, self::COUNTERS_REPLICA_CONNECTION] as $connection) {

                config()->set('sso.rate_limits.connection', $connection);

                self::replicaMigration('2026_10_31_000001_create_sso_rate_limits_table.php')->up(); // @phpstan-ignore method.notFound
            }
        }

        config()->set('sso.rate_limits.connection', $counters);

        $manager->setDefaultConnection(self::SPLIT_CONNECTION);
    }

    /**
     * Copy the row as it stands on the primary to the replica, so a later
     * change on the primary leaves the replica stale.
     *
     * @param  string  $table
     * @param  mixed  $key
     * @param  string  $column
     * @param  string  $primary
     * @param  string  $replica
     * @return void
     */
    protected function copyRowToReplica(
        string $table,
        mixed $key,
        string $column = 'id',
        string $primary = self::PRIMARY_CONNECTION,
        string $replica = self::REPLICA_CONNECTION,
    ): void {
        $row = DB::connection($primary)->table($table)->where($column, $key)->first();

        self::assertNotNull($row, "The row to copy to the replica is not on the primary of {$table}.");

        DB::connection($replica)->table($table)->where($column, $key)->delete();
        DB::connection($replica)->table($table)->insert((array) $row);
    }

    /**
     * Delete the row from the replica only.
     *
     * @param  string  $table
     * @param  mixed  $key
     * @param  string  $column
     * @param  string  $replica
     * @return void
     */
    protected function deleteRowFromReplica(string $table, mixed $key, string $column = 'id', string $replica = self::REPLICA_CONNECTION): void
    {
        DB::connection($replica)->table($table)->where($column, $key)->delete();
    }

    /**
     * Delete the temporary SQLite files.
     *
     * @return void
     */
    protected function removeLaggingReplicaFiles(): void
    {
        foreach ($this->laggingReplicaFiles as $file) {

            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        $this->laggingReplicaFiles = [];
    }

    /**
     * Register direct connections to new primary and replica files, and a split
     * connection over them.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  string  $split
     * @param  string  $primaryName
     * @param  string  $replicaName
     * @return void
     */
    private function registerLaggingConnection(ConfigRepository $config, string $split, string $primaryName, string $replicaName): void
    {
        $primary = $this->createLaggingReplicaFile();
        $replica = $this->createLaggingReplicaFile();

        $config->set('database.connections.' . $primaryName, ['driver' => 'sqlite', 'database' => $primary, 'prefix' => '']);
        $config->set('database.connections.' . $replicaName, ['driver' => 'sqlite', 'database' => $replica, 'prefix' => '']);

        // Testbench inspects the top-level `database`; Laravel uses read/write.
        $config->set('database.connections.' . $split, [
            'driver'   => 'sqlite',
            'database' => $primary,
            'read'     => ['database' => $replica],
            'write'    => ['database' => $primary],
            'sticky'   => false,
            'prefix'   => '',
        ]);
    }

    /**
     * Create an empty temporary SQLite database file.
     *
     * @return string
     */
    private function createLaggingReplicaFile(): string
    {
        $file = tempnam(sys_get_temp_dir(), 'sso-replica-');

        self::assertIsString($file);

        $this->laggingReplicaFiles[] = $file;

        return $file;
    }

    /**
     * The shipped migration of the file name.
     *
     * @param  string  $file
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function replicaMigration(string $file): object
    {
        return require dirname(__DIR__, 2) . '/database/migrations/' . $file;
    }
}
