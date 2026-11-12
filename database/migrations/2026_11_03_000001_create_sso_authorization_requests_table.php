<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Create the authorisation requests table.
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

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'authorization_requests.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->char('id', 26)->primary();

            // The only flow identifier ever shown.
            $blueprint->string('reference', 64);

            // SHA-256 of the OIDC state or SAML RelayState, never stored raw.
            $blueprint->char('state_digest', 64);

            // No foreign key: deleting a connection deletes its requests in the
            // same transaction, whatever the engine.
            $blueprint->string('purpose', 16);
            $blueprint->string('application', 64);
            $blueprint->char('connection_id', 26);

            // Whether the response must return iss (RFC 9207).
            $blueprint->string('expected_issuer', 1024)->nullable();
            $blueprint->boolean('issuer_required')->default(false);

            // The encrypted verifier is the package's own with the provider,
            // never the client's.
            $blueprint->char('nonce_digest', 64)->nullable();
            $blueprint->text('code_verifier')->nullable();
            $blueprint->string('saml_request_id', 255)->nullable();

            // S256 challenge of the client's verifier.
            $blueprint->char('handoff_challenge', 43);

            // Rechecked under the completion's lock, so a trust change made
            // before the request was stored still refuses the flow.
            $blueprint->unsignedBigInteger('trust_version');

            $blueprint->string('identity_type', 255)->nullable();
            $blueprint->string('identity_id', 255)->nullable();
            $blueprint->string('session_id', 255)->nullable();

            $blueprint->dateTime('expires_at', 0);
            $blueprint->dateTime('consumed_at', 0)->nullable();
            $blueprint->dateTime('verified_at', 0)->nullable();
            $blueprint->dateTime('voided_at', 0)->nullable();
            $blueprint->dateTime('completed_at', 0)->nullable();
            $blueprint->dateTime('created_at', 0);
            $blueprint->dateTime('updated_at', 0);

            $blueprint->unique(['reference'], self::indexName($table, 'reference_unique'));
            $blueprint->unique(['state_digest'], self::indexName($table, 'state_unique'));
            $blueprint->unique(['connection_id', 'saml_request_id'], self::indexName($table, 'saml_request_unique'));
            $blueprint->index(['connection_id', 'completed_at'], self::indexName($table, 'connection_index'));
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
        return StorageConnection::connectionFor('authorization_requests.table');
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
        return StorageConnection::table('authorization_requests.table');
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
