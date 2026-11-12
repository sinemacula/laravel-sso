<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Create the connections table.
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

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'connections.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            // Lower-case ULID, the `{connection}` in the endpoints.
            $blueprint->char('id', 26)->primary();

            $blueprint->string('tenant_id');
            $blueprint->string('protocol', 64);
            $blueprint->string('display_name');

            // Secrets apart from settings, as name => ciphertext, so a read can
            // say which are set without decrypting one.
            $blueprint->json('settings');
            $blueprint->longText('secrets')->nullable();
            $blueprint->json('attribute_mapping');

            $blueprint->boolean('enabled')->default(false);

            // Enforcement can be turned on only with such a connection.
            $blueprint->boolean('has_completed_sign_in')->default(false);

            // Raised by each link, request or handoff code inserted, so a
            // PostgreSQL REPEATABLE READ reader that locks the row later fails
            // to serialise instead of missing the insert.
            $blueprint->unsignedBigInteger('links_version')->default(0);
            $blueprint->unsignedBigInteger('flows_version')->default(0);

            // Never raised by an additive certificate.
            $blueprint->unsignedBigInteger('trust_version')->default(0);

            $blueprint->boolean('linking_enabled')->default(false);
            $blueprint->string('linking_issuer_class', 32)->nullable();
            $blueprint->string('linking_organization_claim', 255)->nullable();
            $blueprint->string('linking_organization_value', 255)->nullable();
            $blueprint->string('linking_saml_attribute', 1024)->nullable();
            $blueprint->string('linking_saml_attribute_format', 255)->nullable();
            $blueprint->dateTime('linking_acknowledged_at', 0)->nullable();

            // Raised by linking setting changes; voids reservations, not flows.
            $blueprint->unsignedBigInteger('linking_version')->default(0);

            // Unset accepts nothing.
            $blueprint->json('evidence_policy')->nullable();

            // A refresh's write must match its claim token, so one whose claim
            // expired and was taken over writes nothing.
            $blueprint->unsignedBigInteger('metadata_version')->default(0);
            $blueprint->dateTime('metadata_fetched_at', 0)->nullable();
            $blueprint->dateTime('metadata_valid_until', 0)->nullable();
            $blueprint->dateTime('metadata_refresh_at', 0)->nullable();
            $blueprint->unsignedInteger('metadata_refresh_failures')->default(0);
            $blueprint->dateTime('metadata_claimed_until', 0)->nullable();
            $blueprint->char('metadata_claim_token', 32)->nullable();

            // An OIDC connection's JWKS, stored here so no cache is needed. The
            // suppressed count is capped so a flood writes the row boundedly.
            $blueprint->longText('jwks')->nullable();
            $blueprint->unsignedBigInteger('jwks_version')->default(0);
            $blueprint->dateTime('jwks_fetched_at', 0)->nullable();
            $blueprint->dateTime('jwks_refetch_at', 0)->nullable();
            $blueprint->char('jwks_claim_token', 32)->nullable();
            $blueprint->unsignedInteger('jwks_refetch_suppressed')->default(0);

            $blueprint->dateTime('created_at', 0);
            $blueprint->dateTime('updated_at', 0);

            // Short names, so a long configured table name still fits MySQL's
            // 64-character identifiers.
            $blueprint->index(['tenant_id'], self::indexName($table, 'tenant_index'));
            $blueprint->index(['metadata_refresh_at'], self::indexName($table, 'refresh_index'));
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
        return StorageConnection::connectionFor('connections.table');
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
        return StorageConnection::table('connections.table');
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
