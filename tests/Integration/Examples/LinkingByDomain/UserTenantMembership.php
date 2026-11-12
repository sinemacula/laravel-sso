<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\LinkingByDomain;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;

/**
 * The example application's tenant membership: a current principal of the
 * tenant the person has accepted, read under the user's guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class UserTenantMembership implements TenantMembership
{
    /**
     * The user's current, accepted membership of the tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\MembershipStanding
     */
    #[\Override]
    public function standing(IdentityReference $identity, string $tenantId): MembershipStanding
    {
        if (!Users::hasLockedUser($identity)) {
            return MembershipStanding::none();
        }

        $acceptedAt = DB::connection(StorageConnection::name())->table(Users::PRINCIPALS)
            ->useWritePdo()
            ->where('user_id', $identity->id)
            ->where('tenant_id', $tenantId)
            ->whereNull('revoked_at')
            ->whereNotNull('accepted_at')
            ->min('accepted_at');

        return is_string($acceptedAt) ? MembershipStanding::accepted(CarbonImmutable::parse($acceptedAt, 'UTC')) : MembershipStanding::none();
    }
}
