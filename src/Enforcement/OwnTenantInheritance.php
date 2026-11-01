<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;

/**
 * The default enforcement inheritance (SSO-4.2): each tenant's own setting
 * applies to it alone, and no tenant inherits another's. An application whose
 * tenants inherit an ancestor's rule binds its own contract.
 *
 * It holds nothing, so it is bound as a singleton.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OwnTenantInheritance implements EnforcementInheritance
{
    /**
     * The tenant itself, whatever the application.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @return string
     */
    #[\Override]
    public function enforcingTenant(string $tenantId, string $application): string
    {
        return $tenantId;
    }
}
