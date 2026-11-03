<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\LinkingByDomain;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;

/**
 * The example application's principal scope (SSO-8.8): a user's principals are
 * their rows in the application's `tenant_principals` table, each a membership
 * of a tenant or, with no tenant, a platform principal. Under the user's guard,
 * which `GrantPrincipal` takes after `ScopeWidening`, it reads the complete
 * set, and answers `within_tenant` only when every current principal is of the
 * tenant; an identity that is not one of the application's users is `unknown`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class UserPrincipalScope implements PrincipalScope
{
    /**
     * Where the user's complete set of principals stands against the tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
     */
    #[\Override]
    public function judge(IdentityReference $identity, string $tenantId): ScopeVerdict
    {
        if (!Users::hasLockedUser($identity)) {
            return ScopeVerdict::UNKNOWN;
        }

        $outside = DB::connection(StorageConnection::name())->table(Users::PRINCIPALS)
            ->useWritePdo()
            ->where('user_id', $identity->id)
            ->whereNull('revoked_at')
            ->where(static fn (Builder $query): Builder => $query->whereNull('tenant_id')->orWhere('tenant_id', '<>', $tenantId))
            ->exists();

        return $outside ? ScopeVerdict::OUTSIDE_TENANT : ScopeVerdict::WITHIN_TENANT;
    }
}
