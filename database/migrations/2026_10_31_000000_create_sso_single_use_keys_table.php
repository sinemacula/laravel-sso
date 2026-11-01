<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Create the single-use keys table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return new class extends Migration {
    /**
     * Run the migrations.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Sso\Database\TableAlreadyExistsException
     */
    public function up(): void
    {
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($this->table(), 'single_use.table');

        $schema->create($this->table(), static function (Blueprint $blueprint): void {
            $blueprint->bigIncrements('id');

            // What the key is (`saml_assertion`, `authorization_request`,
            // `handoff_code`), as the caller names it.
            $blueprint->string('namespace', 64);

            // The lower-case hex SHA-256 digest of the key: the key may be a
            // secret (a handoff code), so the table never holds it.
            $blueprint->char('key_digest', 64);

            // Whole seconds in UTC, whatever the application timezone, so a
            // daylight-saving change never repeats a value; compared with the
            // store's clock, and indexed for pruning expired keys.
            $blueprint->dateTime('expires_at', 0)->index();

            // A key is held once in its namespace: the index is what answers
            // `seen`, atomically, however many servers record at once.
            $blueprint->unique(['namespace', 'key_digest']);
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function down(): void
    {
        Schema::connection($this->getConnection())->dropIfExists($this->table());
    }

    /**
     * The connection the table lives on, the one the model reads and writes it
     * on: the storage connection (see `StorageConnection::connectionFor()`).
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[Override]
    public function getConnection(): ?string
    {
        return StorageConnection::connectionFor('single_use.table');
    }

    /**
     * The configured table name.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function table(): string
    {
        return StorageConnection::table('single_use.table');
    }
};
