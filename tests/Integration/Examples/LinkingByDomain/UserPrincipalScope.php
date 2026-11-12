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
 * The example application's principal scope: `within_tenant` only when every
 * current principal, read under the user's guard, is of the tenant.
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
