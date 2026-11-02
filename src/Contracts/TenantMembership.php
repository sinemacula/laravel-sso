<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;

/**
 * Tenant membership contract (SSO-8.8): whether an identity holds a current
 * membership of a tenant, and when the person, not only an administrator,
 * accepted it. A membership counts for linking by a verified domain only when
 * it was accepted before the domain's current verification
 * (`accepted_at < verified_at`), so a tenant that claims a domain cannot add
 * people and then capture them; a creation time an administrator set is never
 * an acceptance time.
 *
 * Protection through admission: the answer is read at completion and again
 * inside the redeemer's transaction, and it must stay true until that commits.
 * A writer that revokes a membership takes the guard this contract documents to
 * the redeemer, after the package's locks (`docs/design/linking.md`).
 *
 * The default, `Linking\NoTenantMembership`, answers no membership. Missing,
 * revoked or unknown all refuse. An implementation reads from the write
 * connection (SSO-11.3), keeps nothing of one call for the next (SSO-11.2), and
 * lets an error propagate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface TenantMembership
{
    /**
     * The identity's current membership of the tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\MembershipStanding
     */
    public function standing(IdentityReference $identity, string $tenantId): MembershipStanding;
}
