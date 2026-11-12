<?php

declare(strict_types = 1);

namespace Tests\Integration\Connections;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Sso\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the connections migration. `#[CoversNothing]` because
 * PHPUnit cannot attribute coverage to an anonymous migration class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class ConnectionsMigrationTest extends TestCase
{
    /** @var string Absolute path to the shipped connections migration. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_01_000000_create_sso_connections_table.php';

    /** @var string The table's default name. */
    private const string TABLE = 'sso_connections';

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
     * Drop the table under any name a test gave it.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(self::TABLE);
        Schema::dropIfExists('idp_connections');

        parent::tearDown();
    }

    /**
     * The table has exactly these columns and nullability, keyed by id.
     *
     * @return void
     */
    public function testCreatesTheColumns(): void
    {
        $columns = array_column(Schema::getColumns(self::TABLE), 'nullable', 'name');

        ksort($columns);

        self::assertSame([
            'attribute_mapping'             => false,
            'created_at'                    => false,
            'display_name'                  => false,
            'enabled'                       => false,
            'evidence_policy'               => true,
            'flows_version'                 => false,
            'has_completed_sign_in'         => false,
            'id'                            => false,
            'jwks'                          => true,
            'jwks_claim_token'              => true,
            'jwks_fetched_at'               => true,
            'jwks_refetch_at'               => true,
            'jwks_refetch_suppressed'       => false,
            'jwks_version'                  => false,
            'linking_acknowledged_at'       => true,
            'linking_enabled'               => false,
            'linking_issuer_class'          => true,
            'linking_organization_claim'    => true,
            'linking_organization_value'    => true,
            'linking_saml_attribute'        => true,
            'linking_saml_attribute_format' => true,
            'linking_version'               => false,
            'links_version'                 => false,
            'metadata_claim_token'          => true,
            'metadata_claimed_until'        => true,
            'metadata_fetched_at'           => true,
            'metadata_refresh_at'           => true,
            'metadata_refresh_failures'     => false,
            'metadata_valid_until'          => true,
            'metadata_version'              => false,
            'protocol'                      => false,
            'secrets'                       => true,
            'settings'                      => false,
            'tenant_id'                     => false,
            'trust_version'                 => false,
            'updated_at'                    => false,
        ], $columns);

        $primary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => $index['primary']));

        self::assertCount(1, $primary);
        self::assertSame(['id'], $primary[0]['columns']);
    }

    /**
     * The tenant and the refresh due time are indexed, neither uniquely.
     *
     * @return void
     */
    public function testIndexesTheTenantAndTheRefreshDue(): void
    {
        $secondary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$index['primary']));

        usort($secondary, static fn (array $one, array $other): int => strcmp($one['name'], $other['name']));

        self::assertSame([
            ['sso_connections_refresh_index', ['metadata_refresh_at'], false],
            ['sso_connections_tenant_index', ['tenant_id'], false],
        ], array_map(static fn (array $index): array => [$index['name'], $index['columns'], $index['unique']], $secondary));
    }

    /**
     * A minimal row is disabled, with zeroed versions and counters and no
     * refresh or JWKS state.
     *
     * @return void
     */
    public function testANewRowIsDisabledAndHasCompletedNoSignIn(): void
    {
        DB::table(self::TABLE)->insert([
            'id'                => '01jbexampleconnection00000',
            'tenant_id'         => 'tenant-1',
            'protocol'          => 'oidc',
            'display_name'      => 'Example',
            'settings'          => '{}',
            'attribute_mapping' => '{}',
            'created_at'        => '2026-11-01 09:30:00',
            'updated_at'        => '2026-11-01 09:30:00',
        ]);

        $row = DB::table(self::TABLE)->first();

        self::assertNotNull($row);
        self::assertFalse((bool) $row->enabled);
        self::assertFalse((bool) $row->has_completed_sign_in);
        self::assertSame(0, (int) $row->links_version);
        self::assertSame(0, (int) $row->flows_version);
        self::assertSame([0, 0, 0], [(int) $row->trust_version, (int) $row->metadata_version, (int) $row->metadata_refresh_failures]);
        self::assertSame([null, null, null, null], [$row->metadata_fetched_at, $row->metadata_valid_until, $row->metadata_refresh_at, $row->metadata_claimed_until]);
        self::assertSame([null, 0, null, null, null], [$row->jwks, (int) $row->jwks_version, $row->jwks_fetched_at, $row->jwks_refetch_at, $row->jwks_claim_token]);
        self::assertSame(0, (int) $row->jwks_refetch_suppressed);
        self::assertNull($row->secrets);
    }

    /**
     * An existing table is refused before any change, naming the setting that
     * renames it.
     *
     * @return void
     */
    public function testRefusesAnExistingTable(): void
    {
        $this->expectException(TableAlreadyExistsException::class);
        $this->expectExceptionMessage('Set `connections.table` in config/sso.php');

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
     * The table and its index take the configured name.
     *
     * @return void
     */
    public function testCreatesTheTableUnderItsConfiguredName(): void
    {
        config()->set('sso.connections.table', 'idp_connections');

        try {
            $this->migration()->up(); // @phpstan-ignore method.notFound

            self::assertTrue(Schema::hasTable('idp_connections'));
            self::assertContains('idp_connections_tenant_index', array_column(Schema::getIndexes('idp_connections'), 'name'));
        } finally {
            config()->set('sso.connections.table', self::TABLE);
        }
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
