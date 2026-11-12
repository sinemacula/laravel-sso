<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Create the links table.
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

            // No foreign key: deleting a connection deletes its links in the
            // same transaction, whatever the engine.
            $blueprint->char('connection_id', 26);

            // The subject is kept byte for byte, never trimmed or normalised.
            $blueprint->string('issuer', 1024);
            $blueprint->string('name_id_format', 255)->nullable();
            $blueprint->binary('subject');

            // SHA-256 of issuer, format and subject, so uniqueness is exact
            // whatever the engine's collation.
            $blueprint->char('subject_key', 64);

            $blueprint->string('identity_type', 255);
            $blueprint->string('identity_id', 255);

            $blueprint->string('state', 16);
            $blueprint->dateTime('suspended_at', 0)->nullable();

            // A value of LinkOrigin.
            $blueprint->string('provenance', 32)->default('link_purpose');

            // A reservation's binding, all cleared on activation.
            $blueprint->char('reservation_id', 26)->nullable();
            $blueprint->dateTime('reservation_expires_at', 0)->nullable();
            $blueprint->string('reservation_reference', 64)->nullable();
            $blueprint->string('reservation_handoff', 255)->nullable();
            $blueprint->char('reservation_email_digest', 64)->nullable();
            $blueprint->string('reservation_organization', 255)->nullable();
            $blueprint->char('reservation_domain_id', 26)->nullable();
            $blueprint->unsignedBigInteger('reservation_domain_generation')->nullable();
            $blueprint->unsignedBigInteger('reservation_linking_version')->nullable();

            $blueprint->dateTime('last_used_at', 0)->nullable();
            $blueprint->dateTime('created_at', 0);
            $blueprint->dateTime('updated_at', 0);

            $blueprint->unique(['connection_id', 'subject_key'], self::indexName($table, 'subject_unique'));
            $blueprint->unique(['reservation_id'], self::indexName($table, 'reservation_unique'));
            $blueprint->index(['connection_id', 'reservation_domain_id'], self::indexName($table, 'reservation_domain_index'));
            $blueprint->index(['identity_type', 'identity_id', 'connection_id'], self::indexName($table, 'identity_index'));
            $blueprint->index(['state', 'reservation_expires_at', 'id'], self::indexName($table, 'reservation_expiry_index'));
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
