<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Create the domains table: the email domains each connection has claimed, and
 * whether and since when each is verified.
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

            // The connection that claimed the domain. No foreign key: deleting
            // a connection deletes its domains in the same transaction,
            // whatever the engine.
            $blueprint->char('connection_id', 26);

            // The normalised domain: lower-case ASCII (IDNA), no trailing dot.
            $blueprint->string('domain', 253);

            // The domain again while it is verified, and null otherwise, so the
            // unique index lets a domain be verified for one connection at a
            // time, across every tenant, however the claims race.
            $blueprint->string('verified_domain', 253)->nullable();

            // The claim's state: pending, verified or lapsed.
            $blueprint->string('state', 16);

            // The TXT record's name under the domain as it was claimed, and the
            // random token the record must carry, which is published in DNS and
            // so not a secret, but never put in an event.
            $blueprint->string('record_name', 63);
            $blueprint->char('verification_token', 64);

            // Raised each time the domain becomes verified, and never lowered:
            // a reservation binds it, so one made under an earlier verification
            // never activates under a later one.
            $blueprint->unsignedBigInteger('verification_generation')->default(0);

            // Whole seconds in UTC, from the package's clock. A pending claim
            // expires; a verified domain keeps the time it became verified
            // until it lapses, and records each successful check. A domain
            // whose record has gone has linking suspended at once and lapses at
            // the end of the grace period. The lease keeps one server's recheck
            // of the domain from overlapping another's.
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

            // One claim of a domain per connection; one verified connection per
            // domain; a claim or a verification locks every claim of its
            // domain; the recheck reads verified domains by their last
            // successful check, and pruning pages pending claims by expiry, by
            // keyset.
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
