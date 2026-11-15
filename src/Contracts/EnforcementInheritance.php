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
     * Answer every tenant the answer depends on, from the tenant itself to the
     * one whose rule applies, last.
     *
     * Ask `$isConfigured` whether a tenant has a stored rule, never anything
     * else, and let what it throws propagate; read the tree current or fail
     * with a retryable concurrency error.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @param  \Closure(string): bool  $isConfigured
     * @return non-empty-list<string>
     */
    public function enforcementPath(string $tenantId, string $application, \Closure $isConfigured): array;
}
