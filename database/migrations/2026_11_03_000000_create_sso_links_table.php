<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Create the links table: each connection's issuer and subject associated with
 * an identity.
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

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'links.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->char('id', 26)->primary();

            // The connection the link was made through. No foreign key:
            // deleting a connection deletes its links in the same transaction,
            // whatever the engine.
            $blueprint->char('connection_id', 26);

            // The issuer and, for SAML, the subject's NameID format, kept as
            // received; the subject byte for byte, in a binary column, never
            // trimmed or normalised.
            $blueprint->string('issuer', 1024);
            $blueprint->string('name_id_format', 255)->nullable();
            $blueprint->binary('subject');

            // The lower-case hex SHA-256 of the issuer, the format and the
            // subject, each length-prefixed: unique with the connection, so one
            // subject is linked once however two creations race, and compared
            // exactly whatever the engine's collation.
            $blueprint->char('subject_key', 64);

            // The identity, an opaque reference the application gives.
            $blueprint->string('identity_type', 255);
            $blueprint->string('identity_id', 255);

            // Active, or reserved by a completion that matched the subject by a
            // verified domain until its handoff is redeemed, with when the
            // reservation expires and the request it was made for.
            $blueprint->string('state', 16);
            $blueprint->dateTime('reservation_expires_at', 0)->nullable();
            $blueprint->string('reservation_reference', 64)->nullable();

            // Made by a verified domain, until a confirming link clears it.
            $blueprint->boolean('domain_provenance')->default(false);

            // Whole seconds in UTC, from the package's clock.
            $blueprint->dateTime('last_used_at', 0)->nullable();
            $blueprint->dateTime('created_at', 0);
            $blueprint->dateTime('updated_at', 0);

            // One link per subject in a connection; an identity's links, by
            // connection, for listing and for the link limit.
            $blueprint->unique(['connection_id', 'subject_key'], self::indexName($table, 'subject_unique'));
            $blueprint->index(['identity_type', 'identity_id', 'connection_id'], self::indexName($table, 'identity_index'));
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
        return StorageConnection::connectionFor('links.table');
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
        return StorageConnection::table('links.table');
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
