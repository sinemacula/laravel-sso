<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Create the handoff codes table: the codes the package's own store issued,
 * each only as a digest.
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

            // The lower-case hex SHA-256 of the code: the code itself is never
            // stored.
            $blueprint->char('code_digest', 64);

            // What the code is bound to: the purpose, the application, the
            // connection, the request's public reference and the S256 challenge
            // of the client's verifier. No foreign key: deleting a connection
            // deletes its codes in the same transaction, whatever the engine.
            $blueprint->string('purpose', 16);
            $blueprint->string('application', 64);
            $blueprint->char('connection_id', 26);
            $blueprint->string('request_reference', 64);
            $blueprint->char('handoff_challenge', 43);

            // The identity a link or reauthenticate flow was started for, the
            // session a reauthenticate flow was started on, and the identity
            // the result's link resolved to at completion.
            $blueprint->string('identity_type', 255)->nullable();
            $blueprint->string('identity_id', 255)->nullable();
            $blueprint->string('session_id', 255)->nullable();
            $blueprint->string('linked_identity_type', 255)->nullable();
            $blueprint->string('linked_identity_id', 255)->nullable();

            // The link the result resolved to at completion, so a link removed
            // and made again is told apart from the one observed; and the
            // reservation a result holding no link was bound to.
            $blueprint->string('link_id', 255)->nullable();
            $blueprint->char('reservation_id', 26)->nullable();

            // The verified result, serialised and encrypted.
            $blueprint->longText('result');

            // The enforcement version checked at completion, and the latest end
            // of the application's session the provider's deadline sets.
            $blueprint->string('enforcement_version', 255)->nullable();
            $blueprint->dateTime('session_not_after', 0)->nullable();

            // Whole seconds in UTC, from the package's clock: when it expires,
            // was redeemed, and was voided by a change to its connection.
            $blueprint->dateTime('expires_at', 0);
            $blueprint->dateTime('redeemed_at', 0)->nullable();
            $blueprint->dateTime('voided_at', 0)->nullable();
            $blueprint->dateTime('created_at', 0);
            $blueprint->dateTime('updated_at', 0);

            // A redemption finds its code by digest; a change to a connection
            // voids its unredeemed codes; pruning reads codes by expiry.
            $blueprint->unique(['code_digest'], self::indexName($table, 'code_unique'));
            $blueprint->index(['connection_id', 'redeemed_at'], self::indexName($table, 'connection_index'));
            $blueprint->index(['expires_at'], self::indexName($table, 'expiry_index'));
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
