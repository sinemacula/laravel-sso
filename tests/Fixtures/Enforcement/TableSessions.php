<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Enforcement;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * An application's sessions as a table on the package's storage connection, and
 * the revocation contract that removes them, as an adapter writing through the
 * same Laravel connection would (decision D5): a redeemer writes a session
 * inside its own transaction once a redemption answers `redeemed`, and a
 * revocation deletes, with one statement, every session the scope no longer
 * allows. A delete is a current read on every engine, so it removes a session
 * another transaction committed after the revoking transaction's snapshot.
 *
 * A test may set `afterRevoking` to run once the sessions are deleted, still
 * inside the change's transaction, to hold that transaction open.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TableSessions implements SessionRevocation
{
    /** @var string The sessions table. */
    public const string TABLE = 'sso_test_sessions';

    /** @var ?\Closure(): void Run once the sessions are deleted, inside the change's transaction. */
    public ?\Closure $afterRevoking = null;

    /**
     * Create the sessions table on the storage connection.
     *
     * @return void
     */
    public static function create(): void
    {
        Schema::connection(StorageConnection::name())->create(self::TABLE, static function (Blueprint $table): void {
            $table->id();
            $table->string('tenant_id');
            $table->char('connection_id', 26);
            $table->char('link_id', 26)->nullable();
        });
    }

    /**
     * Drop the sessions table.
     *
     * @return void
     */
    public static function drop(): void
    {
        Schema::connection(StorageConnection::name())->dropIfExists(self::TABLE);
    }

    /**
     * Write a session of the tenant, established through the connection, in
     * whatever transaction the storage connection has open.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  ?string  $linkId
     * @return void
     */
    public static function write(string $tenantId, string $connectionId, ?string $linkId = null): void
    {
        DB::connection(StorageConnection::name())->table(self::TABLE)->insert(['tenant_id' => $tenantId, 'connection_id' => $connectionId, 'link_id' => $linkId]);
    }

    /**
     * The connection each committed session of the tenant was established
     * through, in id order.
     *
     * @param  string  $tenantId
     * @return list<string>
     */
    public static function connectionsOf(string $tenantId): array
    {
        /** @var list<string> */
        return DB::connection(StorageConnection::name())->table(self::TABLE)->where('tenant_id', $tenantId)->orderBy('id')->pluck('connection_id')->all();
    }

    /**
     * Delete every session the scope no longer allows: for a tenant's
     * enforcement, each of the tenant not established through one of the
     * policy's connections; for a widened scope, each established through the
     * link; otherwise each established through the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return void
     */
    #[\Override]
    public function revoke(RevocationScope $scope): void
    {
        $sessions = DB::connection(StorageConnection::name())->table(self::TABLE)->where('tenant_id', $scope->tenantId);

        match ($scope->kind) {
            RevocationScopeKind::TENANT        => $sessions->whereNotIn('connection_id', $scope->policy->connectionIds ?? [])->delete(),
            RevocationScopeKind::IDENTITY_LINK => $sessions->where('link_id', $scope->linkId)->delete(),
            default                            => $sessions->where('connection_id', $scope->connectionId)->delete(),
        };

        if ($this->afterRevoking === null) {
            return;
        }

        ($this->afterRevoking)();
    }
}
