<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

/**
 * Decides which tenant's enforcement applies to sessions in a tenant, since the
 * tenant tree belongs to the application.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EnforcementInheritance
{
    /**
     * Answer the tenant itself or the ancestor whose rule applies.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @return string
     */
    public function enforcingTenant(string $tenantId, string $application): string;
}
