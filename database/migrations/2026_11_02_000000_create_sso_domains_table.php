<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Create the claimed email domains table.
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

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'domains.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->char('id', 26)->primary();

            // No foreign key: deleting a connection deletes its domains in the
            // same transaction, whatever the engine.
            $blueprint->char('connection_id', 26);

            // Lower-case ASCII (IDNA), no trailing dot.
            $blueprint->string('domain', 253);

            // Set only while verified, so the unique index allows one verified
            // connection per domain across every tenant.
            $blueprint->string('verified_domain', 253)->nullable();

            $blueprint->string('state', 16);

            // The token is published in DNS, so not a secret, but never put in
            // an event.
            $blueprint->string('record_name', 63);
            $blueprint->char('verification_token', 64);

            // Never lowered, so a reservation made under an earlier
            // verification never activates under a later one.
            $blueprint->unsignedBigInteger('verification_generation')->default(0);

            $blueprint->dateTime('claimed_at', 0);
            $blueprint->dateTime('pending_expires_at', 0)->nullable();
            $blueprint->dateTime('verified_at', 0)->nullable();
            $blueprint->dateTime('last_successful_check_at', 0)->nullable();
            $blueprint->dateTime('linking_suspended_at', 0)->nullable();
            $blueprint->dateTime('lapses_at', 0)->nullable();
            $blueprint->dateTime('lapsed_at', 0)->nullable();
            $blueprint->dateTime('recheck_leased_until', 0)->nullable();
            $blueprint->dateTime('created_at', 0);
            $blueprint->dateTime('updated_at', 0);

            $blueprint->unique(['connection_id', 'domain'], self::indexName($table, 'connection_domain_unique'));
            $blueprint->unique(['verified_domain'], self::indexName($table, 'verified_unique'));
            $blueprint->index(['domain'], self::indexName($table, 'domain_index'));
            $blueprint->index(['state', 'last_successful_check_at'], self::indexName($table, 'recheck_index'));
            $blueprint->index(['state', 'pending_expires_at', 'id'], self::indexName($table, 'pending_index'));
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
        return StorageConnection::connectionFor('domains.table');
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
        return StorageConnection::table('domains.table');
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
