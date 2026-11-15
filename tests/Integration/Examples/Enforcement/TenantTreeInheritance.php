<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Enforcement;

use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;

/**
 * The example application's enforcement inheritance: a tenant follows the root
 * its record names.
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
     * Every tenant the answer depends on: the tenant, then the root of its
     * branch, on every application.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @param  \Closure(string): bool  $isConfigured
     * @return non-empty-list<string>
     */
    #[\Override]
    public function enforcementPath(string $tenantId, string $application, \Closure $isConfigured): array
    {
        unset($application, $isConfigured);

        // Asked at READ COMMITTED, where each read sees what has committed
        $tenant = Tenant::query()->findOrFail($tenantId);

        return $tenant->enforcement_root_id === null ? [$tenant->id] : [$tenant->id, $tenant->enforcement_root_id];
    }
    // @snippet-end enforcement-inheritance-tenant
}
