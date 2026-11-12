<?php

declare(strict_types = 1);

namespace Tests\Integration\Enforcement;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Sso\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the shipped enforcement migration.
 *
 * Covers nothing: PHPUnit cannot attribute coverage to an anonymous class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class EnforcementMigrationTest extends TestCase
{
    /** @var string Absolute path to the shipped enforcement migration. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000001_create_sso_enforcement_table.php';

    /** @var string The table's default name. */
    private const string TABLE = 'sso_enforcement';

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
     * The table has these columns and a unique index on the tenant's hash.
     *
     * @return void
     */
    public function testCreatesTheColumnsAndTheTenantIndex(): void
    {
        $columns = array_column(Schema::getColumns(self::TABLE), 'nullable', 'name');

        ksort($columns);

        self::assertSame([
            'changed_at'     => true,
            'connection_ids' => false,
            'created_at'     => false,
            'enabled'        => false,
            'id'             => false,
            'tenant_hash'    => false,
            'tenant_id'      => false,
            'updated_at'     => false,
            'version'        => true,
        ], $columns);

        $indexes = [];

        foreach (Schema::getIndexes(self::TABLE) as $index) {
            $indexes[$index['primary'] ? 'primary' : $index['name']] = ['columns' => $index['columns'], 'unique' => $index['unique']];
        }

        ksort($indexes);

        self::assertSame([
            'primary'                       => ['columns' => ['id'], 'unique' => true],
            'sso_enforcement_tenant_unique' => ['columns' => ['tenant_hash'], 'unique' => true],
        ], $indexes);
    }

    /**
     * Tenants whose ids differ only in case get rows of their own.
     *
     * @return void
     */
    public function testKeepsOneRowPerTenant(): void
    {
        DB::table(self::TABLE)->insert(self::row('01jbexampleenforcement0001', 'acme'));
        DB::table(self::TABLE)->insert(self::row('01jbexampleenforcement0002', 'Acme'));

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row('01jbexampleenforcement0003', 'acme'));
    }

    /**
     * The migration refuses an existing table and the rollback drops it.
     *
     * @return void
     */
    public function testRefusesAnExistingTableAndRollsBack(): void
    {
        try {
            $this->migration()->up(); // @phpstan-ignore method.notFound
            self::fail('The migration ran over an existing table.');
        } catch (TableAlreadyExistsException $exception) {
            self::assertStringContainsString('Set `enforcement.table` in config/sso.php', $exception->getMessage());
        }

        $this->migration()->down(); // @phpstan-ignore method.notFound

        self::assertFalse(Schema::hasTable(self::TABLE));
    }

    /**
     * A disabled row for the tenant.
     *
     * @param  string  $id
     * @param  string  $tenantId
     * @return array<string, mixed>
     */
    private static function row(string $id, string $tenantId): array
    {
        return [
            'id'             => $id,
            'tenant_id'      => $tenantId,
            'tenant_hash'    => hash('sha256', $tenantId),
            'enabled'        => false,
            'connection_ids' => '[]',
            'version'        => '01jbexampleversion00000001',
            'changed_at'     => '2026-11-01 09:30:00',
            'created_at'     => '2026-11-01 09:30:00',
            'updated_at'     => '2026-11-01 09:30:00',
        ];
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
