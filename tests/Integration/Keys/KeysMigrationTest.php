<?php

declare(strict_types = 1);

namespace Tests\Integration\Keys;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Sso\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the keys and certificates migration. Marked
 * `#[CoversNothing]` as a migration is an anonymous class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class KeysMigrationTest extends TestCase
{
    /** @var string Absolute path to the shipped keys migration. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_01_000001_create_sso_keys_table.php';

    /** @var string The table's default name. */
    private const string TABLE = 'sso_keys';

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
     * The table has exactly these columns, the optional ones nullable, with the
     * id as primary key.
     *
     * @return void
     */
    public function testCreatesTheColumns(): void
    {
        $columns = array_column(Schema::getColumns(self::TABLE), 'nullable', 'name');

        ksort($columns);

        self::assertSame([
            'certificate'               => true,
            'connection_id'             => false,
            'created_at'                => false,
            'expiry_claimed_until'      => true,
            'expiry_notified_at'        => true,
            'expiry_notified_threshold' => true,
            'fingerprint'               => false,
            'id'                        => false,
            'key_bits'                  => false,
            'key_type'                  => false,
            'made_current_at'           => true,
            'not_after'                 => true,
            'not_before'                => true,
            'private_key'               => true,
            'public_key'                => false,
            'retiring_until'            => true,
            'state'                     => true,
            'updated_at'                => false,
            'use'                       => false,
        ], $columns);

        $primary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => $index['primary']));

        self::assertSame(['id'], $primary[0]['columns']);
    }

    /**
     * The fingerprint is unique per use in a connection, and rotation and
     * expiry lookups are indexed.
     *
     * @return void
     */
    public function testIndexesTheFingerprintTheRotationAndTheExpiry(): void
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
            'sso_keys_expiry_index'       => ['columns' => ['not_after', 'id'], 'unique' => false],
            'sso_keys_fingerprint_unique' => ['columns' => ['connection_id', 'use', 'fingerprint'], 'unique' => true],
            'sso_keys_rotation_index'     => ['columns' => ['connection_id', 'use', 'state'], 'unique' => false],
        ], $indexes);
    }

    /**
     * The same fingerprint for the same use in a connection is refused; another
     * use or connection is not.
     *
     * @return void
     */
    public function testRefusesTheSameKeyTwiceForOneUseOfAConnection(): void
    {
        $row = [
            'connection_id' => '01jbexampleconnection00000',
            'use'           => 'idp_signing',
            'key_type'      => 'rsa',
            'key_bits'      => 2048,
            'public_key'    => 'public-key-pem',
            'fingerprint'   => str_repeat('a', 64),
            'created_at'    => '2026-11-01 09:30:00',
            'updated_at'    => '2026-11-01 09:30:00',
        ];

        DB::table(self::TABLE)->insert(['id' => '01jbexamplekey000000000001'] + $row);
        DB::table(self::TABLE)->insert(['id' => '01jbexamplekey000000000002', 'use' => 'sp_signing'] + $row);
        DB::table(self::TABLE)->insert(['id' => '01jbexamplekey000000000003', 'connection_id' => '01jbexampleconnection00001'] + $row);

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(['id' => '01jbexamplekey000000000004'] + $row);
    }

    /**
     * An existing table is refused before any change, naming the rename
     * setting; the rollback drops it.
     *
     * @return void
     */
    public function testRefusesAnExistingTableAndRollsBack(): void
    {
        try {
            $this->migration()->up(); // @phpstan-ignore method.notFound
            self::fail('The migration ran over an existing table.');
        } catch (TableAlreadyExistsException $exception) {
            self::assertStringContainsString('Set `keys.table` in config/sso.php', $exception->getMessage());
        }

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
