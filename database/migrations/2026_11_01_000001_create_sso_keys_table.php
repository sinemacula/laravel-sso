<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Create the keys and certificates table: each connection's own key pairs and
 * the identity provider certificates it trusts.
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

            // The connection the row belongs to. No foreign key: deleting a
            // connection deletes its keys in the same transaction, whatever the
            // engine.
            $blueprint->char('connection_id', 26);

            // `sp_signing`, `sp_encryption`, `client_assertion` or
            // `idp_signing`; `next`, `current` or `retiring` for a key of the
            // service provider's own, and none for a trusted certificate.
            $blueprint->string('use', 32);
            $blueprint->string('state', 16)->nullable();

            $blueprint->string('key_type', 8);
            $blueprint->unsignedSmallInteger('key_bits');

            // PEM. The private key is the SecretEncrypter's ciphertext, and
            // only a key of the service provider's own has one.
            $blueprint->text('certificate')->nullable();
            $blueprint->text('public_key');
            $blueprint->longText('private_key')->nullable();

            // Lower-case hex SHA-256 of the certificate's DER, or of the public
            // key's when there is no certificate.
            $blueprint->char('fingerprint', 64);

            // Whole seconds in UTC. The certificate's dates are reported, never
            // enforced; the rotation times come from the package's clock.
            $blueprint->dateTime('not_before', 0)->nullable();
            $blueprint->dateTime('not_after', 0)->nullable();
            $blueprint->dateTime('made_current_at', 0)->nullable();
            $blueprint->dateTime('retiring_until', 0)->nullable();

            // The expiry report's marker, written only once the warning has
            // been dispatched: the most urgent threshold warned of, in days,
            // and when; and until when one reporter holds the key to send it.
            $blueprint->unsignedSmallInteger('expiry_notified_threshold')->nullable();
            $blueprint->dateTime('expiry_notified_at', 0)->nullable();
            $blueprint->dateTime('expiry_claimed_until', 0)->nullable();

            $blueprint->dateTime('created_at', 0);
            $blueprint->dateTime('updated_at', 0);

            // One row per key or certificate of a use in a connection; the
            // rotation reads a connection's keys of one use by state; the
            // expiry report pages by the end of validity, by keyset.
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
     * An index name built from the table's, as Laravel builds one: lower case,
     * with a schema's dot as an underscore.
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
