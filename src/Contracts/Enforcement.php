<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;

/**
 * Decides whether sessions in a tenant must be established through one of its
 * connections, and which connections satisfy that.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Enforcement
{
    /**
     * Read current state from the write connection, never a cache; let errors
     * propagate rather than answer "not required".
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
     *
     * @throws \InvalidArgumentException
     */
    public function policy(string $tenantId, string $application): EnforcementPolicy;
}
