<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Enforcement;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * The example application's session revocation (SSO-4.5): it marks revoked, in
 * the application's own `sessions` table and through the package's storage
 * connection, the sessions each scope names: those of the enforcing tenant and
 * every tenant that inherits its rule not established through a satisfying
 * connection, every session through a connection, or every session through a
 * link.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RevokeSessions implements SessionRevocation
{
    // @snippet-start revoke-sessions
    /**
     * Revoke the sessions of the scope, inside the package's transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return void
     */
    #[\Override]
    public function revoke(RevocationScope $scope): void
    {
        // On the package's storage connection, to commit with the change
        $sessions = DB::connection(StorageConnection::name())->table('sessions')->whereNull('revoked_at');

        $revoked = match ($scope->kind) {
            RevocationScopeKind::TENANT => $sessions
                // The scope names only the enforcing tenant: include every
                // tenant that inherits its rule
                ->whereIn('tenant_id', $this->tenantsUnderRule($scope->tenantId))
                // A session with no SSO connection (a password session) holds
                // NULL, and `NULL NOT IN (...)` is never true, so it must be
                // named: it is exactly what the rule exists to remove
                ->where(static fn (Builder $query): Builder => $query->whereNull('sso_connection_id')
                    ->orWhereNotIn('sso_connection_id', $scope->policy->connectionIds ?? [])),
            // Here `$scope->tenantId` is the connection's tenant, not the
            // tenant a session is active in now, which a switch changes:
            // connection ids are unique, so never narrow by `tenant_id`
            RevocationScopeKind::CONNECTION => $sessions->where('sso_connection_id', $scope->connectionId),
            // A removed link and a widened scope name the link
            // (`$scope->linkId`); with no link column, revoke the identity's
            // sessions through the connection (`sso_connection_id` and
            // `user_id`), which is broader and never narrower
            default => $sessions->where('sso_link_id', $scope->linkId),
        };

        // The sessions of identities your exemption contract exempts may stay
        $revoked->update(['revoked_at' => now(), 'revoked_reason' => $scope->reason->value]);
    }

    /**
     * The enforcing tenant and every tenant that inherits its rule: the reverse
     * of your `EnforcementInheritance`, answered by your tenant model.
     *
     * @param  string  $enforcingTenantId
     * @return array<array-key, mixed>
     */
    private function tenantsUnderRule(string $enforcingTenantId): array
    {
        return Tenant::query()->whereKey($enforcingTenantId)
            ->orWhere('enforcement_root_id', $enforcingTenantId)
            ->pluck('id')
            ->all();
    }
    // @snippet-end revoke-sessions
}
