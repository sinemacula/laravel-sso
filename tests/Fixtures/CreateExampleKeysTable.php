<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * A migration written as every shipped migration is: on the connection its
 * table lives on, under its configured name, guarded against a table that is
 * already there.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CreateExampleKeysTable extends Migration
{
    /** @var string The key, under `sso.`, of the setting that names the table. */
    private const string TABLE = 'single_use.table';

    /**
     * Run the migration.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Database\TableAlreadyExistsException
     */
    public function up(): void
    {
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists(StorageConnection::table(self::TABLE), self::TABLE);

        $schema->create(StorageConnection::table(self::TABLE), static function (Blueprint $table): void {
            $table->id();
            $table->string('namespace', 64);
        });
    }

    /**
     * Reverse the migration.
     *
     * @return void
     */
    public function down(): void
    {
        Schema::connection($this->getConnection())->dropIfExists(StorageConnection::table(self::TABLE));
    }

    /**
     * The connection the table lives on, the one its model reads and writes.
     *
     * @return ?string
     */
    #[\Override]
    public function getConnection(): ?string
    {
        return StorageConnection::connectionFor(self::TABLE);
    }
}
