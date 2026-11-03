<?php

declare(strict_types = 1);

namespace Tests\Integration\SingleUse;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Sso\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the shipped single-use keys migration, on whichever
 * engine the suite runs against: the table's shape, its unique index, the guard
 * against an existing table, the rollback, and the connection it runs on.
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
final class SingleUseKeysMigrationTest extends TestCase
{
    /** @var string Absolute path to the shipped single-use keys migration. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The table's default name. */
    private const string TABLE = 'sso_single_use_keys';

    /** @var string The second connection the storage is moved to. */
    private const string STORE = 'package_store';

    /**
     * Run the shipped migration, with the schema builder's default time
     * precision raised to microseconds while it runs, so the whole-second
     * precision is what the migration itself declares.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

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
     * storage.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        config()->set('sso.storage.connection', null);

        Schema::dropIfExists(self::TABLE);

        parent::tearDown();
    }

    /**
     * The table has exactly the id, the namespace, the digest and the expiry,
     * none of them nullable, with the id as its primary key.
     *
     * @return void
     */
    public function testCreatesTheIdNamespaceDigestAndExpiryColumns(): void
    {
        $columns = array_column(Schema::getColumns(self::TABLE), 'nullable', 'name');

        ksort($columns);

        self::assertSame(['expires_at' => false, 'id' => false, 'key_digest' => false, 'namespace' => false], $columns);

        $primary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => $index['primary']));

        self::assertCount(1, $primary);
        self::assertSame(['id'], $primary[0]['columns']);
    }

    /**
     * The secondary indexes are the unique index on the namespace and the
     * digest, which answers `seen`, and the index on the expiry and the id, in
     * the order pruning pages by keyset.
     *
     * @return void
     */
    public function testIndexesTheKeyUniquelyAndTheExpiryForPruning(): void
    {
        $secondary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$index['primary']));

        $indexes = array_map(static fn (array $index): array => ['columns' => $index['columns'], 'unique' => $index['unique']], $secondary);

        usort($indexes, static fn (array $a, array $b): int => $a['columns'][0] <=> $b['columns'][0]);

        self::assertSame([
            ['columns' => ['expires_at', 'id'], 'unique' => false],
            ['columns' => ['namespace', 'key_digest'], 'unique' => true],
        ], $indexes);
    }

    /**
     * A second row with the same namespace and digest is refused by the index;
     * the same digest in another namespace is not.
     *
     * @return void
     */
    public function testRefusesADuplicateKeyInItsNamespace(): void
    {
        $row = ['namespace' => 'handoff_code', 'key_digest' => hash('sha256', 'key'), 'expires_at' => '2026-10-31 12:01:00'];

        DB::table(self::TABLE)->insert($row);
        DB::table(self::TABLE)->insert(['namespace' => 'saml_assertion'] + $row);

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(['expires_at' => '2026-10-31 13:00:00'] + $row);
    }

    /**
     * The expiry is stored to the whole second.
     *
     * @return void
     */
    public function testStoresTheExpiryToTheWholeSecond(): void
    {
        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        self::assertDoesNotMatchRegularExpression('/\([1-9]\)/', $types['expires_at']);

        DB::table(self::TABLE)->insert(['namespace' => 'handoff_code', 'key_digest' => hash('sha256', 'key'), 'expires_at' => '2039-02-28 23:59:59']);

        self::assertSame('2039-02-28 23:59:59', DB::table(self::TABLE)->value('expires_at'));
    }

    /**
     * The digest column is exactly as long as a SHA-256 hex digest, and the
     * namespace as long as the longest one allowed.
     *
     * @return void
     */
    public function testSizesTheDigestAndTheNamespace(): void
    {
        if (Schema::getConnection()->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite does not record a length for string columns.');
        }

        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        self::assertStringContainsString('(64)', $types['key_digest']);
        self::assertStringContainsString('(64)', $types['namespace']);
    }

    /**
     * Running the migration again finds its table and stops before changing it,
     * naming the setting that renames it.
     *
     * @return void
     */
    public function testRefusesToRunOverAnExistingTable(): void
    {
        DB::table(self::TABLE)->insert(['namespace' => 'handoff_code', 'key_digest' => hash('sha256', 'key'), 'expires_at' => '2026-10-31 12:01:00']);

        try {
            $this->migration()->up(); // @phpstan-ignore method.notFound

            self::fail('Expected the migration to refuse the existing table.');
        } catch (TableAlreadyExistsException $exception) {
            self::assertStringContainsString('for the \'' . self::TABLE . '\' table', $exception->getMessage());
            self::assertStringContainsString('Set `single_use.table` in config/sso.php', $exception->getMessage());
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
        config()->set('sso.single_use.table', 'replay_keys');

        $migration = $this->migration();

        $migration->up(); // @phpstan-ignore method.notFound

        try {
            self::assertTrue(Schema::hasTable('replay_keys'));
        } finally {
            $migration->down(); // @phpstan-ignore method.notFound
        }

        self::assertFalse(Schema::hasTable('replay_keys'));
        self::assertTrue(Schema::hasTable(self::TABLE));
    }

    /**
     * With the storage on a second connection, the migration creates and drops
     * the table there, and only there.
     *
     * @return void
     */
    public function testRunsOnTheStorageConnection(): void
    {
        Schema::dropIfExists(self::TABLE);

        config()->set('sso.storage.connection', self::STORE);

        $migration = $this->migration();

        self::assertSame(self::STORE, $migration->getConnection());

        $migration->up(); // @phpstan-ignore method.notFound

        self::assertTrue(Schema::connection(self::STORE)->hasTable(self::TABLE));
        self::assertFalse(Schema::connection('testing')->hasTable(self::TABLE));

        $migration->down(); // @phpstan-ignore method.notFound

        self::assertFalse(Schema::connection(self::STORE)->hasTable(self::TABLE));

        config()->set('sso.storage.connection', '');

        self::assertNull($this->migration()->getConnection());
    }

    /**
     * A storage connection that is not a name is refused, as the model refuses
     * it, rather than creating the table on the default connection.
     *
     * @return void
     */
    public function testRefusesAStorageConnectionThatIsNotAName(): void
    {
        Schema::dropIfExists(self::TABLE);

        config()->set('sso.storage.connection', [self::STORE]);

        try {
            $this->migration()->up(); // @phpstan-ignore method.notFound

            self::fail('Expected the migration to refuse the connection.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('`sso.storage.connection` must be a connection name', $exception->getMessage());
        }

        config()->set('sso.storage.connection', null);

        self::assertFalse(Schema::hasTable(self::TABLE));
    }

    /**
     * Add the second connection the storage is moved to.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('database.connections.' . self::STORE, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
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
            self::fail('The single-use keys migration did not return a Migration instance.');
        }

        return $migration;
    }
}
