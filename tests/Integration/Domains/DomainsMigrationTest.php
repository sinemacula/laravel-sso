<?php

declare(strict_types = 1);

namespace Tests\Integration\Domains;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Sso\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the shipped domains migration, on whichever engine the
 * suite runs against: the table's shape, its indexes, one claim of a domain per
 * connection, one verified connection per domain whatever the tenant, any
 * number of claims of a domain that is not verified, the guard against an
 * existing table and the rollback.
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
final class DomainsMigrationTest extends TestCase
{
    /** @var string Absolute path to the shipped domains migration. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000000_create_sso_domains_table.php';

    /** @var string The table's default name. */
    private const string TABLE = 'sso_domains';

    /**
     * Run the shipped migration.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

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
     * The table has exactly these columns, those a claim's state leaves empty
     * nullable, with the id as its primary key.
     *
     * @return void
     */
    public function testCreatesTheColumns(): void
    {
        $columns = array_column(Schema::getColumns(self::TABLE), 'nullable', 'name');

        ksort($columns);

        self::assertSame([
            'claimed_at'               => false,
            'connection_id'            => false,
            'created_at'               => false,
            'domain'                   => false,
            'id'                       => false,
            'lapsed_at'                => true,
            'lapses_at'                => true,
            'last_successful_check_at' => true,
            'linking_suspended_at'     => true,
            'pending_expires_at'       => true,
            'recheck_leased_until'     => true,
            'record_name'              => false,
            'state'                    => false,
            'updated_at'               => false,
            'verification_generation'  => false,
            'verification_token'       => false,
            'verified_at'              => true,
            'verified_domain'          => true,
        ], $columns);

        $primary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => $index['primary']));

        self::assertSame(['id'], $primary[0]['columns']);
    }

    /**
     * The secondary indexes: one claim per connection, one verified connection
     * per domain, every claim of a domain, the recheck's and the pruning's
     * reads.
     *
     * @return void
     */
    public function testIndexesTheClaimsTheVerificationTheRecheckAndThePruning(): void
    {
        $indexes = [];

        foreach (Schema::getIndexes(self::TABLE) as $index) {

            if ($index['primary']) {
                continue;
            }

            $indexes[$index['name']] = ['columns' => $index['columns'], 'unique' => $index['unique']];
        }

        ksort($indexes);

        self::assertSame([
            'sso_domains_connection_domain_unique' => ['columns' => ['connection_id', 'domain'], 'unique' => true],
            'sso_domains_domain_index'             => ['columns' => ['domain'], 'unique' => false],
            'sso_domains_pending_index'            => ['columns' => ['state', 'pending_expires_at', 'id'], 'unique' => false],
            'sso_domains_recheck_index'            => ['columns' => ['state', 'last_successful_check_at'], 'unique' => false],
            'sso_domains_verified_unique'          => ['columns' => ['verified_domain'], 'unique' => true],
        ], $indexes);
    }

    /**
     * Several connections may claim a domain while none holds it verified; a
     * second claim of it by one connection is refused.
     *
     * @return void
     */
    public function testRefusesASecondClaimOfADomainByOneConnection(): void
    {
        DB::table(self::TABLE)->insert(self::row('01jbexampledomain000000001', '01jbexampleconnection00001'));
        DB::table(self::TABLE)->insert(self::row('01jbexampledomain000000002', '01jbexampleconnection00002'));

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row('01jbexampledomain000000003', '01jbexampleconnection00001'));
    }

    /**
     * A domain is verified for one connection at a time, of any tenant.
     *
     * @return void
     */
    public function testRefusesASecondVerificationOfADomain(): void
    {
        DB::table(self::TABLE)->insert(['verified_domain' => 'example.com', 'state' => 'verified'] + self::row('01jbexampledomain000000001', '01jbexampleconnection00001'));

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(['verified_domain' => 'example.com', 'state' => 'verified'] + self::row('01jbexampledomain000000002', '01jbexampleconnection00002'));
    }

    /**
     * Running the migration over an existing table is refused before any
     * change, naming the setting that renames the table; the rollback drops it.
     *
     * @return void
     */
    public function testRefusesAnExistingTableAndRollsBack(): void
    {
        try {
            $this->migration()->up(); // @phpstan-ignore method.notFound
            self::fail('The migration ran over an existing table.');
        } catch (TableAlreadyExistsException $exception) {
            self::assertStringContainsString('Set `domains.table` in config/sso.php', $exception->getMessage());
        }

        $this->migration()->down(); // @phpstan-ignore method.notFound

        self::assertFalse(Schema::hasTable(self::TABLE));
    }

    /**
     * A pending claim of `example.com` by the connection.
     *
     * @param  string  $id
     * @param  string  $connectionId
     * @return array<string, int|string|null>
     */
    private static function row(string $id, string $connectionId): array
    {
        return [
            'id'                      => $id,
            'connection_id'           => $connectionId,
            'domain'                  => 'example.com',
            'verified_domain'         => null,
            'state'                   => 'pending',
            'record_name'             => '_sso-verification',
            'verification_generation' => 0,
            'verification_token'      => str_repeat('a', 64),
            'claimed_at'              => '2026-11-01 09:30:00',
            'created_at'              => '2026-11-01 09:30:00',
            'updated_at'              => '2026-11-01 09:30:00',
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
