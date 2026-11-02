<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Create the connections table: each tenant's trust in one identity provider
 * over one protocol.
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
            // A lower-case ULID, the `{connection}` of the connection's
            // endpoints.
            $blueprint->char('id', 26)->primary();

            // The tenant is an opaque string id the application gives; the
            // protocol a registered driver's name. Both are fixed at creation.
            $blueprint->string('tenant_id');
            $blueprint->string('protocol', 64);
            $blueprint->string('display_name');

            // The settings by name, with no secret among them; the secrets
            // apart from them, as a JSON object of each secret's name and its
            // ciphertext from the SecretEncrypter, so the settings can be
            // compared and reported by name, and a read can say which secrets
            // are set without decrypting one.
            $blueprint->json('settings');
            $blueprint->longText('secrets')->nullable();
            $blueprint->json('attribute_mapping');

            $blueprint->boolean('enabled')->default(false);

            // Set once a sign_in through the connection has been redeemed;
            // enforcement can be turned on only with such a connection.
            $blueprint->boolean('has_completed_sign_in')->default(false);

            // Raised by every link created through the connection, under the
            // connection's lock, so the insert also writes this row: a
            // PostgreSQL REPEATABLE READ transaction that then locks the row
            // fails to serialise rather than miss the link (SubjectMigration).
            $blueprint->unsignedBigInteger('links_version')->default(0);

            // Raised by every authorisation request stored and every handoff
            // code issued through the connection, under its lock, so either
            // insert also writes this row: a PostgreSQL REPEATABLE READ change
            // that then locks the row fails to serialise rather than leave the
            // new request or code unvoided (InFlightVoider).
            $blueprint->unsignedBigInteger('flows_version')->default(0);

            // Raised under the connection's lock by every change that voids
            // what is in flight through it (a trust change, a disable) and by
            // enabling it; never by an additive certificate. A flow that holds
            // no request to void (an unsolicited SAML response) and a metadata
            // refresh capture it before their slow steps and compare it under
            // the lock, so a change made meanwhile refuses them.
            $blueprint->unsignedBigInteger('trust_version')->default(0);

            // The metadata refresh (SSO-2.8), of a SAML connection's metadata
            // or an OIDC connection's discovery document and JWKS: raised by
            // every refresh that writes, so two refreshes compare and set; the
            // last validated fetch and the earliest validUntil of what it
            // applied, from which the settings expire; when the next attempt is
            // due, how many have failed in a row (the backoff), until when a
            // server's claim on a refresh in progress holds, and the random
            // token that claim was made with, which a refresh's write must
            // match, so one whose claim expired and was taken over writes
            // nothing.
            $blueprint->unsignedBigInteger('metadata_version')->default(0);
            $blueprint->dateTime('metadata_fetched_at', 0)->nullable();
            $blueprint->dateTime('metadata_valid_until', 0)->nullable();
            $blueprint->dateTime('metadata_refresh_at', 0)->nullable();
            $blueprint->unsignedInteger('metadata_refresh_failures')->default(0);
            $blueprint->dateTime('metadata_claimed_until', 0)->nullable();
            $blueprint->char('metadata_claim_token', 32)->nullable();

            // An OIDC connection's JWKS (SSO-7.3), stored with it so no cache
            // is needed: the public keys the package admitted, as a JSON list
            // of their public members; the version every write of it raises, so
            // a refetch and a refresh compare and set; when it was last
            // validated, from which it expires once a refresh has written the
            // connection; until when no unknown-kid refetch may start (the
            // cooldown, claimed before the fetch and kept whether it succeeds
            // or not); and the random token the refetch's claim was made with,
            // which its write must match.
            $blueprint->longText('jwks')->nullable();
            $blueprint->unsignedBigInteger('jwks_version')->default(0);
            $blueprint->dateTime('jwks_fetched_at', 0)->nullable();
            $blueprint->dateTime('jwks_refetch_at', 0)->nullable();
            $blueprint->char('jwks_claim_token', 32)->nullable();

            // Whole seconds in UTC, from the package's clock.
            $blueprint->dateTime('created_at', 0);
            $blueprint->dateTime('updated_at', 0);

            // Named from the table, so a long configured name still fits
            // MySQL's 64-character identifiers.
            $blueprint->index(['tenant_id'], self::indexName($table, 'tenant_index'));

            // The scheduled refresh reads the connections whose next attempt is
            // due.
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
