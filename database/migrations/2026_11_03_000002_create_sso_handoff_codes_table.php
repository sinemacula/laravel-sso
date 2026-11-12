<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Create the handoff codes table.
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

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'handoff_codes.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->char('id', 26)->primary();

            // SHA-256 of the code, which is never stored.
            $blueprint->char('code_digest', 64);

            // No foreign key: deleting a connection deletes its codes in the
            // same transaction, whatever the engine.
            $blueprint->string('purpose', 16);
            $blueprint->string('application', 64);
            $blueprint->char('connection_id', 26);
            $blueprint->string('request_reference', 64);
            $blueprint->char('handoff_challenge', 43);

            $blueprint->string('identity_type', 255)->nullable();
            $blueprint->string('identity_id', 255)->nullable();
            $blueprint->string('session_id', 255)->nullable();
            $blueprint->string('linked_identity_type', 255)->nullable();
            $blueprint->string('linked_identity_id', 255)->nullable();

            // The link id tells a link removed and made again from the one
            // observed at completion.
            $blueprint->string('link_id', 255)->nullable();
            $blueprint->char('reservation_id', 26)->nullable();

            // The verified result, serialised and encrypted.
            $blueprint->longText('result');

            $blueprint->unsignedBigInteger('trust_version');

            // The latest session end the provider's deadline allows.
            $blueprint->dateTime('session_not_after', 0)->nullable();

            $blueprint->dateTime('expires_at', 0);
            $blueprint->dateTime('redeemed_at', 0)->nullable();
            $blueprint->dateTime('voided_at', 0)->nullable();
            $blueprint->dateTime('created_at', 0);
            $blueprint->dateTime('updated_at', 0);

            $blueprint->unique(['code_digest'], self::indexName($table, 'code_unique'));
            $blueprint->index(['connection_id', 'redeemed_at'], self::indexName($table, 'connection_index'));
            $blueprint->index(['expires_at', 'id'], self::indexName($table, 'expiry_index'));
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
        return StorageConnection::connectionFor('handoff_codes.table');
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
        return StorageConnection::table('handoff_codes.table');
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
