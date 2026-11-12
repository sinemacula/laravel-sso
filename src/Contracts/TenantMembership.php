<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;

/**
 * Reports an identity's current membership of a tenant and when the person
 * accepted it, for linking by a verified domain.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface TenantMembership
{
    /**
     * Read from the write connection; an administrator's creation time is never
     * an acceptance time.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\MembershipStanding
     */
    public function standing(IdentityReference $identity, string $tenantId): MembershipStanding;
}
