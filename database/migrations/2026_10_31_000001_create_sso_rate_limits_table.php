<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Create the rate limits table.
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
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($this->table(), 'rate_limits.table');

        $schema->create($this->table(), static function (Blueprint $blueprint): void {
            // HMAC-SHA256 hex digest, keyed from the application key, of what
            // the counter counts (see CounterKeys), so the table alone gives
            // none of it back.
            $blueprint->char('key', 64)->primary();
            $blueprint->unsignedInteger('hits');

            // Whole seconds in UTC, whatever the application timezone, so a
            // daylight-saving change never repeats a value; compared with the
            // window boundaries the limiter computes.
            $blueprint->dateTime('window_ends_at', 0);

            // Pruning reads ended windows in this order, by keyset.
            $blueprint->index(['window_ends_at', 'key']);
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
     * The connection the counters live on, the one the model reads and writes
     * them on: `sso.rate_limits.connection`, or the storage connection (see
     * `StorageConnection::connectionFor()`).
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[Override]
    public function getConnection(): ?string
    {
        return StorageConnection::connectionFor('rate_limits.table');
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
        return StorageConnection::table('rate_limits.table');
    }
};
