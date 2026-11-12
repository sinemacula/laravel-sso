<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Create the keys and certificates table.
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
        $table  = $this->table();
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'keys.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->char('id', 26)->primary();

            // No foreign key: deleting a connection deletes its keys in the
            // same transaction, whatever the engine.
            $blueprint->char('connection_id', 26);

            // State is null for a trusted certificate.
            $blueprint->string('use', 32);
            $blueprint->string('state', 16)->nullable();

            $blueprint->string('key_type', 8);
            $blueprint->unsignedSmallInteger('key_bits');

            // PEM; the private key is encrypted and only the SP's own has one.
            $blueprint->text('certificate')->nullable();
            $blueprint->text('public_key');
            $blueprint->longText('private_key')->nullable();

            // SHA-256 hex of the certificate's DER, else the public key's.
            $blueprint->char('fingerprint', 64);

            // Certificate dates are reported, never enforced.
            $blueprint->dateTime('not_before', 0)->nullable();
            $blueprint->dateTime('not_after', 0)->nullable();
            $blueprint->dateTime('made_current_at', 0)->nullable();
            $blueprint->dateTime('retiring_until', 0)->nullable();

            // Written only once the expiry warning has been dispatched.
            $blueprint->unsignedSmallInteger('expiry_notified_threshold')->nullable();
            $blueprint->dateTime('expiry_notified_at', 0)->nullable();
            $blueprint->dateTime('expiry_claimed_until', 0)->nullable();

            $blueprint->dateTime('created_at', 0);
            $blueprint->dateTime('updated_at', 0);

            $blueprint->unique(['connection_id', 'use', 'fingerprint'], self::indexName($table, 'fingerprint_unique'));
            $blueprint->index(['connection_id', 'use', 'state'], self::indexName($table, 'rotation_index'));
            $blueprint->index(['not_after', 'id'], self::indexName($table, 'expiry_index'));
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
     * The storage connection, which the model uses too.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[Override]
    public function getConnection(): ?string
    {
        return StorageConnection::connectionFor('keys.table');
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
        return StorageConnection::table('keys.table');
    }

    /**
     * An index name built from the table's the way Laravel builds one.
     *
     * @param  string  $table
     * @param  string  $suffix
     * @return string
     */
    private static function indexName(string $table, string $suffix): string
    {
        return str_replace(['-', '.'], '_', strtolower($table)) . '_' . $suffix;
    }
};
