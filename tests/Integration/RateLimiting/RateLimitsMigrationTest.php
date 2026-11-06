<?php

declare(strict_types = 1);

namespace Tests\Integration\RateLimiting;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Sso\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the shipped rate limits migration, on whichever engine
 * the suite runs against: the table's shape, its primary key and its index, the
 * guard against an existing table, the rollback, and the connection it runs on,
 * the counters' own when `sso.rate_limits.connection` names one.
 *
 * Marked `#[CoversNothing]` because a migration is an anonymous class PHPUnit
 * cannot attribute coverage to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class RateLimitsMigrationTest extends TestCase
{
    /** @var string Absolute path to the shipped rate limits migration. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var string The table's default name. */
    private const string TABLE = 'sso_rate_limits';

    /** @var string The second connection the storage is moved to. */
    private const string STORE = 'package_store';

    /** @var string The separate connection the counters are moved to. */
    private const string COUNTERS = 'counters';

    /**
     * Drop the tables an earlier test kept, then run the shipped migration,
     * with the schema builder's default time precision raised to microseconds
     * while it runs, so the whole-second precision is what the migration itself
     * declares.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->dropKeptTables();

        $precision = Builder::$defaultTimePrecision;

        Builder::defaultTimePrecision(6);

        try {
            $this->migration()->up(); // @phpstan-ignore method.notFound
        } finally {
            Builder::defaultTimePrecision($precision);
        }
    }

    /**
     * Drop the table from the default connection, wherever a test moved the
     * counters.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        config()->set('sso.storage.connection', null);
        config()->set('sso.rate_limits.connection', null);

        Schema::dropIfExists(self::TABLE);

        parent::tearDown();
    }

    /**
     * The table has exactly the key, the count and the window's end, none of
     * them nullable, with the key as its primary key.
     *
     * @return void
     */
    public function testCreatesTheKeyHitsAndWindowColumns(): void
    {
        $columns = array_column(Schema::getColumns(self::TABLE), 'nullable', 'name');

        ksort($columns);

        self::assertSame(['hits' => false, 'key' => false, 'window_ends_at' => false], $columns);

        $primary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => $index['primary']));

        self::assertCount(1, $primary);
        self::assertSame(['key'], $primary[0]['columns']);
    }

    /**
     * The one secondary index is on the window's end and the key, in the order
     * pruning pages by keyset.
     *
     * @return void
     */
    public function testIndexesTheWindowForPruning(): void
    {
        $secondary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$index['primary']));

        $indexes = array_map(static fn (array $index): array => ['columns' => $index['columns'], 'unique' => $index['unique']], $secondary);

        self::assertSame([['columns' => ['window_ends_at', 'key'], 'unique' => false]], $indexes);
    }

    /**
     * A second counter under the same key is refused by the primary key.
     *
     * @return void
     */
    public function testRefusesASecondCounterUnderOneKey(): void
    {
        $row = ['key' => hash('sha256', 'counter'), 'hits' => 1, 'window_ends_at' => '2026-10-31 12:01:00'];

        DB::table(self::TABLE)->insert($row);

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(['hits' => 2] + $row);
    }

    /**
     * The window's end is stored to the whole second.
     *
     * @return void
     */
    public function testStoresTheWindowToTheWholeSecond(): void
    {
        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        self::assertDoesNotMatchRegularExpression('/\([1-9]\)/', $types['window_ends_at']);

        DB::table(self::TABLE)->insert(['key' => hash('sha256', 'counter'), 'hits' => 1, 'window_ends_at' => '2039-02-28 23:59:59']);

        self::assertSame('2039-02-28 23:59:59', DB::table(self::TABLE)->value('window_ends_at'));
    }

    /**
     * The key column is exactly as long as a SHA-256 hex digest.
     *
     * @return void
     */
    public function testSizesTheKeyForADigest(): void
    {
        if (Schema::getConnection()->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite does not record a length for string columns.');
        }

        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        self::assertStringContainsString('(64)', $types['key']);
    }

    /**
     * Running the migration again finds its table and stops before changing it,
     * naming the setting that renames it.
     *
     * @return void
     */
    public function testRefusesToRunOverAnExistingTable(): void
    {
        DB::table(self::TABLE)->insert(['key' => hash('sha256', 'counter'), 'hits' => 1, 'window_ends_at' => '2026-10-31 12:01:00']);

        try {
            $this->migration()->up(); // @phpstan-ignore method.notFound

            self::fail('Expected the migration to refuse the existing table.');
        } catch (TableAlreadyExistsException $exception) {
            self::assertStringContainsString('for the \'' . self::TABLE . '\' table', $exception->getMessage());
            self::assertStringContainsString('Set `rate_limits.table` in config/sso.php', $exception->getMessage());
        }

        self::assertSame(1, DB::table(self::TABLE)->count());
    }

    /**
     * Rolling back drops the table, and rolling back again changes nothing.
     *
     * @return void
     */
    public function testDownDropsTheTable(): void
    {
        $migration = $this->migration();

        $migration->down(); // @phpstan-ignore method.notFound

        self::assertFalse(Schema::hasTable(self::TABLE));

        $migration->down(); // @phpstan-ignore method.notFound

        self::assertFalse(Schema::hasTable(self::TABLE));
    }

    /**
     * Under another configured name, the migration creates that table.
     *
     * @return void
     */
    public function testRunsUnderAnotherConfiguredName(): void
    {
        config()->set('sso.rate_limits.table', 'attempt_counters');

        $migration = $this->migration();

        $migration->up(); // @phpstan-ignore method.notFound

        try {
            self::assertTrue(Schema::hasTable('attempt_counters'));
        } finally {
            $migration->down(); // @phpstan-ignore method.notFound
        }

        self::assertFalse(Schema::hasTable('attempt_counters'));
        self::assertTrue(Schema::hasTable(self::TABLE));
    }

    /**
     * With the counters on a connection of their own, the migration creates and
     * drops the table there, and only there, whatever the storage connection.
     *
     * @return void
     */
    public function testRunsOnTheCountersConnection(): void
    {
        Schema::dropIfExists(self::TABLE);

        config()->set('sso.storage.connection', self::STORE);
        config()->set('sso.rate_limits.connection', self::COUNTERS);

        $migration = $this->migration();

        self::assertSame(self::COUNTERS, $migration->getConnection());

        $migration->up(); // @phpstan-ignore method.notFound

        self::assertTrue(Schema::connection(self::COUNTERS)->hasTable(self::TABLE));
        self::assertFalse(Schema::connection(self::STORE)->hasTable(self::TABLE));
        self::assertFalse(Schema::connection('testing')->hasTable(self::TABLE));

        $migration->down(); // @phpstan-ignore method.notFound

        self::assertFalse(Schema::connection(self::COUNTERS)->hasTable(self::TABLE));
    }

    /**
     * Without a counters connection of their own, the migration creates the
     * table on the storage connection.
     *
     * @return void
     */
    public function testRunsOnTheStorageConnectionOtherwise(): void
    {
        Schema::dropIfExists(self::TABLE);

        config()->set('sso.storage.connection', self::STORE);
        config()->set('sso.rate_limits.connection', '');

        $migration = $this->migration();

        self::assertSame(self::STORE, $migration->getConnection());

        $migration->up(); // @phpstan-ignore method.notFound

        self::assertTrue(Schema::connection(self::STORE)->hasTable(self::TABLE));
        self::assertFalse(Schema::connection(self::COUNTERS)->hasTable(self::TABLE));

        $migration->down(); // @phpstan-ignore method.notFound

        self::assertFalse(Schema::connection(self::STORE)->hasTable(self::TABLE));

        config()->set('sso.storage.connection', null);

        self::assertNull($this->migration()->getConnection());
    }

    /**
     * A counters connection that is not a name is refused, as the model refuses
     * it, rather than creating the table on another connection.
     *
     * @return void
     */
    public function testRefusesACountersConnectionThatIsNotAName(): void
    {
        Schema::dropIfExists(self::TABLE);

        config()->set('sso.rate_limits.connection', [self::COUNTERS]);

        try {
            $this->migration()->up(); // @phpstan-ignore method.notFound

            self::fail('Expected the migration to refuse the connection.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('`sso.rate_limits.connection` must be a connection name', $exception->getMessage());
        }

        config()->set('sso.rate_limits.connection', null);

        self::assertFalse(Schema::hasTable(self::TABLE));
    }

    /**
     * Add the second connections the storage and the counters are moved to.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('database.connections.' . self::STORE, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        config()->set('database.connections.' . self::COUNTERS, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
    }

    /**
     * Require the shipped anonymous-class migration and return it.
     *
     * @return \Illuminate\Database\Migrations\Migration
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function migration(): Migration
    {
        $migration = include self::MIGRATION_PATH;

        if (!$migration instanceof Migration) {
            self::fail('The rate limits migration did not return a Migration instance.');
        }

        return $migration;
    }
}
