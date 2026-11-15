<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;

/**
 * Default enforcement inheritance: each tenant's own setting applies to it
 * alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OwnTenantInheritance implements EnforcementInheritance
{
    /**
     * The tenant alone, whatever the application.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @param  \Closure(string): bool  $isConfigured
     * @return non-empty-list<string>
     */
    #[\Override]
    public function enforcementPath(string $tenantId, string $application, \Closure $isConfigured): array
    {
        return [$tenantId];
    }
}
