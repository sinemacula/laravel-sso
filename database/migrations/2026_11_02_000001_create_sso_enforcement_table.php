<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Create the enforcement table: each tenant's rule that sessions active in it
 * are established only through its own connections.
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

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'enforcement.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->char('id', 26)->primary();

            // The tenant is an opaque string id the application gives, fixed at
            // creation. One row per tenant is kept by the lower-case hex
            // SHA-256 of its id rather than by the id itself, so a collation
            // that counts `acme` and `Acme` as equal cannot merge two tenants.
            $blueprint->string('tenant_id');
            $blueprint->char('tenant_hash', 64);

            // Whether the rule is on, and the ids of the tenant's connections
            // that satisfy it, as a JSON list.
            $blueprint->boolean('enabled')->default(false);
            $blueprint->json('connection_ids');

            // A fresh lower-case ULID on every change, which an adapter records
            // against a session to recheck it once it is stale.
            $blueprint->char('version', 26);

            // Whole seconds in UTC, from the package's clock.
            $blueprint->dateTime('changed_at', 0);
            $blueprint->dateTime('created_at', 0);
            $blueprint->dateTime('updated_at', 0);

            $blueprint->unique(['tenant_hash'], self::indexName($table, 'tenant_unique'));
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
        return StorageConnection::connectionFor('enforcement.table');
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
        return StorageConnection::table('enforcement.table');
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
