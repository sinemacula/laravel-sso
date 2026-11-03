<?php

declare(strict_types = 1);

namespace Tests\Integration\Flows;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the shipped links, authorisation requests and handoff
 * codes migrations, on whichever engine the suite runs against: each table's
 * columns and which are nullable, its indexes, its configured name, the guard
 * against an existing table and the rollback.
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
final class FlowTablesMigrationTest extends TestCase
{
    /** @var array<string, array{0: string, 1: string, 2: string}> Each migration's file, its table's key and default name, by table. */
    private const array MIGRATIONS = [
        'links'    => ['2026_11_03_000000_create_sso_links_table.php', 'links.table', 'sso_links'],
        'requests' => ['2026_11_03_000001_create_sso_authorization_requests_table.php', 'authorization_requests.table', 'sso_authorization_requests'],
        'codes'    => ['2026_11_03_000002_create_sso_handoff_codes_table.php', 'handoff_codes.table', 'sso_handoff_codes'],
    ];

    /**
     * Drop every table the tests may have made.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (self::MIGRATIONS as [, , $table]) {
            Schema::dropIfExists($table);
            Schema::dropIfExists("renamed_{$table}");
        }

        parent::tearDown();
    }

    /**
     * Rows of `[table, columns, indexes]`: each table's columns, nullable or
     * not, and its secondary indexes.
     *
     * @return iterable<string, array{0: string, 1: array<string, bool>, 2: array<string, array{columns: list<string>, unique: bool}>}>
     */
    public static function provideTables(): iterable
    {
        yield 'links' => ['links', [
            'connection_id'                 => false,
            'created_at'                    => false,
            'id'                            => false,
            'identity_id'                   => false,
            'identity_type'                 => false,
            'issuer'                        => false,
            'last_used_at'                  => true,
            'name_id_format'                => true,
            'provenance'                    => false,
            'reservation_domain_generation' => true,
            'reservation_domain_id'         => true,
            'reservation_email_digest'      => true,
            'reservation_expires_at'        => true,
            'reservation_handoff'           => true,
            'reservation_id'                => true,
            'reservation_linking_version'   => true,
            'reservation_organization'      => true,
            'reservation_reference'         => true,
            'state'                         => false,
            'subject'                       => false,
            'subject_key'                   => false,
            'suspended_at'                  => true,
            'updated_at'                    => false,
        ], [
            'sso_links_identity_index'           => ['columns' => ['identity_type', 'identity_id', 'connection_id'], 'unique' => false],
            'sso_links_reservation_domain_index' => ['columns' => ['connection_id', 'reservation_domain_id'], 'unique' => false],
            'sso_links_reservation_expiry_index' => ['columns' => ['state', 'reservation_expires_at', 'id'], 'unique' => false],
            'sso_links_reservation_unique'       => ['columns' => ['reservation_id'], 'unique' => true],
            'sso_links_subject_unique'           => ['columns' => ['connection_id', 'subject_key'], 'unique' => true],
        ]];

        yield 'authorisation requests' => ['requests', [
            'application'       => false,
            'code_verifier'     => true,
            'completed_at'      => true,
            'connection_id'     => false,
            'consumed_at'       => true,
            'created_at'        => false,
            'expected_issuer'   => true,
            'expires_at'        => false,
            'handoff_challenge' => false,
            'id'                => false,
            'identity_id'       => true,
            'identity_type'     => true,
            'issuer_required'   => false,
            'nonce_digest'      => true,
            'purpose'           => false,
            'reference'         => false,
            'saml_request_id'   => true,
            'session_id'        => true,
            'state_digest'      => false,
            'trust_version'     => false,
            'updated_at'        => false,
            'verified_at'       => true,
            'voided_at'         => true,
        ], [
            'sso_authorization_requests_connection_index'    => ['columns' => ['connection_id', 'completed_at'], 'unique' => false],
            'sso_authorization_requests_expiry_index'        => ['columns' => ['expires_at', 'id'], 'unique' => false],
            'sso_authorization_requests_reference_unique'    => ['columns' => ['reference'], 'unique' => true],
            'sso_authorization_requests_saml_request_unique' => ['columns' => ['connection_id', 'saml_request_id'], 'unique' => true],
            'sso_authorization_requests_state_unique'        => ['columns' => ['state_digest'], 'unique' => true],
        ]];

        yield 'handoff codes' => ['codes', [
            'application'          => false,
            'code_digest'          => false,
            'connection_id'        => false,
            'created_at'           => false,
            'enforcement_version'  => true,
            'expires_at'           => false,
            'handoff_challenge'    => false,
            'id'                   => false,
            'identity_id'          => true,
            'identity_type'        => true,
            'link_id'              => true,
            'linked_identity_id'   => true,
            'linked_identity_type' => true,
            'purpose'              => false,
            'redeemed_at'          => true,
            'request_reference'    => false,
            'reservation_id'       => true,
            'result'               => false,
            'session_id'           => true,
            'session_not_after'    => true,
            'updated_at'           => false,
            'voided_at'            => true,
        ], [
            'sso_handoff_codes_code_unique'      => ['columns' => ['code_digest'], 'unique' => true],
            'sso_handoff_codes_connection_index' => ['columns' => ['connection_id', 'redeemed_at'], 'unique' => false],
            'sso_handoff_codes_expiry_index'     => ['columns' => ['expires_at', 'id'], 'unique' => false],
        ]];
    }

    /**
     * The table has exactly these columns and secondary indexes, with the id as
     * its primary key.
     *
     * @param  string  $name
     * @param  array<string, bool>  $columns
     * @param  array<string, array{columns: list<string>, unique: bool}>  $indexes
     * @return void
     */
    #[DataProvider('provideTables')]
    public function testCreatesTheTable(string $name, array $columns, array $indexes): void
    {
        [$file, , $table] = self::MIGRATIONS[$name];

        self::migration($file)->up(); // @phpstan-ignore method.notFound

        $found = array_column(Schema::getColumns($table), 'nullable', 'name');

        ksort($found);

        self::assertSame($columns, $found);

        $secondary = [];

        foreach (Schema::getIndexes($table) as $index) {

            if ($index['primary']) {
                self::assertSame(['id'], $index['columns']);
                continue;
            }

            $secondary[$index['name']] = ['columns' => $index['columns'], 'unique' => $index['unique']];
        }

        ksort($secondary);

        self::assertSame($indexes, $secondary);
    }

    /**
     * Each table takes its configured name, and its indexes are named from it.
     *
     * @return void
     */
    public function testEachTableTakesItsConfiguredName(): void
    {
        foreach (self::MIGRATIONS as [$file, $key, $table]) {

            config()->set("sso.{$key}", "renamed_{$table}");

            self::migration($file)->up(); // @phpstan-ignore method.notFound

            self::assertTrue(Schema::hasTable("renamed_{$table}"));
            self::assertFalse(Schema::hasTable($table));
            $secondary = array_values(array_filter(Schema::getIndexes("renamed_{$table}"), static fn (array $index): bool => !$index['primary']));

            self::assertStringStartsWith("renamed_{$table}_", $secondary[0]['name']);
        }
    }

    /**
     * A table that exists already is never touched: the migration fails naming
     * the key that renames it; rolling back drops the table.
     *
     * @return void
     */
    public function testGuardsAnExistingTableAndRollsBack(): void
    {
        foreach (self::MIGRATIONS as [$file, $key, $table]) {

            $migration = self::migration($file);

            $migration->up(); // @phpstan-ignore method.notFound

            try {
                $migration->up(); // @phpstan-ignore method.notFound
                self::fail("The {$table} migration ran over an existing table.");
            } catch (TableAlreadyExistsException $exception) {
                self::assertStringContainsString("Set `{$key}` in config/sso.php", $exception->getMessage());
            }

            $migration->down(); // @phpstan-ignore method.notFound

            self::assertFalse(Schema::hasTable($table));
        }
    }

    /**
     * The shipped migration of the file.
     *
     * @param  string  $file
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function migration(string $file): Migration
    {
        return require __DIR__ . '/../../../database/migrations/' . $file;
    }
}
