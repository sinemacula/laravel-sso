<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Enforcement;

use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;

/**
 * The example application's enforcement inheritance (SSO-4.2): a tenant follows
 * the rule of the root its own tenant record names, on every application, read
 * from the application's tenant model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantTreeInheritance implements EnforcementInheritance
{
    // @snippet-start enforcement-inheritance-tenant
    /**
     * The tenant whose rule applies to sessions active in the tenant: the root
     * of its branch, on every application.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @return string
     */
    #[\Override]
    public function enforcingTenant(string $tenantId, string $application): string
    {
        unset($application);

        // A tenant's place in the tree rarely changes, so a plain read is safe
        // inside the caller's transaction
        $tenant = Tenant::query()->findOrFail($tenantId);

        return $tenant->enforcement_root_id ?? $tenant->id;
    }
    // @snippet-end enforcement-inheritance-tenant
}
