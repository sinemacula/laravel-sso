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

            // Whole seconds in UTC, from the package's clock.
            $blueprint->dateTime('created_at', 0);
            $blueprint->dateTime('updated_at', 0);

            // Named from the table, so a long configured name still fits
            // MySQL's 64-character identifiers.
            $blueprint->index(['tenant_id'], self::indexName($table, 'tenant_index'));
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
