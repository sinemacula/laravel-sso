<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

/**
 * Enforcement inheritance contract (SSO-4.2): which tenant's enforcement
 * applies to sessions active in a tenant, on an application. The tenant tree is
 * the application's and opaque to the package, so whether a tenant inherits an
 * ancestor's rule is the application's to say.
 *
 * It answers one tenant id: the tenant itself, or the ancestor whose rule
 * applies. The default, `Enforcement\OwnTenantInheritance`, answers the tenant
 * itself, so each tenant's own setting applies to it alone. An implementation
 * answers from current state on each call and keeps nothing of one call for the
 * next (SSO-11.2); an error it cannot answer through propagates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EnforcementInheritance
{
    /**
     * The tenant whose enforcement applies to sessions active in the tenant, on
     * the application.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @return string
     */
    public function enforcingTenant(string $tenantId, string $application): string;
}
