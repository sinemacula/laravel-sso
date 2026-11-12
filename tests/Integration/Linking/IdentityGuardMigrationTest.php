<?php

declare(strict_types = 1);

namespace Tests\Integration\Linking;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Sso\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the identity guards migration. `#[CoversNothing]`:
 * PHPUnit cannot attribute coverage to a migration's anonymous class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class IdentityGuardMigrationTest extends TestCase
{
    /** @var string Absolute path to the shipped migration. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_03_000003_create_sso_identity_guards_table.php';

    /** @var string The table's default name. */
    private const string TABLE = 'sso_identity_guards';

    /**
     * Drop the tables an earlier test kept, then run the shipped migration.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->dropKeptTables();

        $this->migration()->up(); // @phpstan-ignore method.notFound
    }

    /**
     * Drop the table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(self::TABLE);

        parent::tearDown();
    }

    /**
     * The table has exactly these columns, and only the marker of a domain link
     * held is nullable: it names nobody.
     *
     * @return void
     */
    public function testTheTableHoldsADigestAMarkerAndATime(): void
    {
        $columns = Schema::getColumnListing(self::TABLE);

        sort($columns);

        self::assertSame(['created_at', 'domain_linked_at', 'id', 'identity_hash'], $columns);

        $nullable = [];

        foreach (Schema::getColumns(self::TABLE) as $column) {
            $nullable[$column['name']] = $column['nullable'];
        }

        ksort($nullable);

        self::assertSame(['created_at' => false, 'domain_linked_at' => true, 'id' => false, 'identity_hash' => false], $nullable);
    }

    /**
     * One row per identity: a second row of a digest is refused by the index.
     *
     * @return void
     */
    public function testADigestHasOneRow(): void
    {
        $digest = str_repeat('a', 64);

        DB::table(self::TABLE)->insert(['id' => str_repeat('1', 26), 'identity_hash' => $digest, 'created_at' => '2026-11-01 09:30:00']);

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(['id' => str_repeat('2', 26), 'identity_hash' => $digest, 'created_at' => '2026-11-01 09:30:00']);
    }

    /**
     * A table already there is never overwritten, naming the setting that
     * renames it.
     *
     * @return void
     */
    public function testAnExistingTableIsRefused(): void
    {
        $this->expectException(TableAlreadyExistsException::class);
        $this->expectExceptionMessage('identity_guards.table');

        $this->migration()->up(); // @phpstan-ignore method.notFound
    }

    /**
     * The rollback drops the table.
     *
     * @return void
     */
    public function testTheRollbackDropsTheTable(): void
    {
        $this->migration()->down(); // @phpstan-ignore method.notFound

        self::assertFalse(Schema::hasTable(self::TABLE));
    }

    /**
     * The shipped migration.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private function migration(): Migration
    {
        return require self::MIGRATION_PATH;
    }
}
