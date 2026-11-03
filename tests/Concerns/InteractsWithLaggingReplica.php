<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\Facades\DB;

/**
 * Builds a read/write split connection whose read replica lags behind the
 * primary, with sticky reads off, so nothing but `useWritePdo()` can reach the
 * primary (SSO-11.3).
 *
 * The default connection becomes `split`, which writes to one SQLite file (the
 * primary) and reads from another (the replica). The shipped tables are created
 * on both, and every row written through `split` lands on the primary only, so
 * a read served by the replica does not see it: a row missing from the replica
 * stands for one newly created. `copyRowToReplica()` puts a row's present
 * version on the replica, so that once the test changes it on the primary the
 * replica holds the stale version: enabled where the primary has disabled,
 * unredeemed where the primary has redeemed, and so on, in both directions.
 *
 * It is SQLite whatever `DB_CONNECTION` says, since two files are the cheapest
 * replica there is. A test calls `configureLaggingReplica()` from its
 * `defineEnvironment()`, `migrateSsoTablesOnPrimaryAndReplica()` from its
 * `setUp()` and `removeLaggingReplicaFiles()` from its `tearDown()`. Counters
 * on a connection of their own get a pair of their own, through
 * `configureLaggingCounters()`.
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

    /** @var list<string> The shipped migrations of every table on the storage connection, in the order they run. */
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
     * Register the primary, replica and split connections and make the split
     * connection the default.
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
     * Register a second lagging split connection for the rate limit counters,
     * and point `sso.rate_limits.connection` at it.
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
     * Run the shipped migrations on the primary and the replica, the counters'
     * on their own pair when they have one, and on the storage pair otherwise.
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
     * Copy a row as it stands on a primary into its replica (the storage pair
     * unless others are named), replacing any version there, so the replica
     * holds this version until the test copies it again. The column is the
     * table's primary key: `key` for the counters, `id` for the rest.
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
     * Delete the row from the replica only, so the replica has lost what the
     * primary still holds.
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
     * Register a direct connection to a new primary file, one to a new replica
     * file, and a split connection that writes to the primary and reads from
     * the replica, sticky reads off.
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

        // The top-level `database` is what Testbench inspects; Laravel uses the
        // `read` and `write` entries for the two PDOs.
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
