<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Database\TableAlreadyExistsException;
use SineMacula\Laravel\Sso\Models\SsoModel;
use Tests\Fixtures\CreateExampleKeysTable;
use Tests\Fixtures\Models\ExampleKey;
use Tests\TestCase;

/**
 * Integration tests that a model and its table's migration agree on connection
 * and name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageConnection::class)]
#[CoversClass(SsoModel::class)]
#[CoversClass(MigrationCollisionGuard::class)]
final class StorageConnectionModelTest extends TestCase
{
    /** @var string The second connection the tables are moved to. */
    private const string STORE = 'package_store';

    /**
     * Drop the tables an earlier test kept.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->dropKeptTables();
    }

    /**
     * The migration and the model meet on the configured connection and table.
     *
     * @return void
     */
    public function testTheModelAndTheMigrationMeetOnTheStorageConnection(): void
    {
        config()->set('sso.storage.connection', self::STORE);
        config()->set('sso.single_use.table', 'replay_keys');

        $migration = new CreateExampleKeysTable;

        $migration->up();

        try {
            self::assertTrue(Schema::connection(self::STORE)->hasTable('replay_keys'));
            self::assertFalse(Schema::connection('testing')->hasTable('replay_keys'));

            $key = ExampleKey::query()->create(['namespace' => 'example']);

            self::assertSame(self::STORE, $key->getConnectionName());
            self::assertSame(['example'], ExampleKey::query()->pluck('namespace')->all());
            self::assertSame(1, DB::connection(self::STORE)->table('replay_keys')->count());
        } finally {
            $migration->down();
        }

        self::assertFalse(Schema::connection(self::STORE)->hasTable('replay_keys'));
    }

    /**
     * Running the migration again stops before changing anything, naming the
     * setting.
     *
     * @return void
     */
    public function testTheMigrationRefusesATableAlreadyThere(): void
    {
        $migration = new CreateExampleKeysTable;

        $migration->up();

        try {
            $migration->up();

            self::fail('Expected the migration to refuse the existing table.');
        } catch (TableAlreadyExistsException $exception) {
            self::assertSame(
                'Cannot install the laravel-sso migration for the \'sso_single_use_keys\' table: a table with that name already exists on connection \'testing\'.'
                . ' Set `single_use.table` in config/sso.php to a different name and re-run the migration.',
                $exception->getMessage(),
            );
        } finally {
            $migration->down();
        }
    }

    /**
     * Add the second connection the tables are moved to.
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
}
