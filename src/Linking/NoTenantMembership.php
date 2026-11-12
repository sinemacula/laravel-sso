<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The default tenant membership contract: the package keeps no memberships.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NoTenantMembership implements TenantMembership
{
    /**
     * Find no membership.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\MembershipStanding
     */
    #[\Override]
    public function standing(IdentityReference $identity, string $tenantId): MembershipStanding
    {
        unset($identity, $tenantId);

        return MembershipStanding::none();
    }
}
