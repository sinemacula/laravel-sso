<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking\Enums;

/**
 * Where an identity's complete set of principals stands against a tenant
 * (SSO-8.8). Only `within_tenant` allows anything; the other two refuse.
 *
 * Backed, and stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ScopeVerdict: string
{
    // Every principal is a membership of the tenant
    case WITHIN_TENANT = 'within_tenant';

    // A platform principal, or a membership of another tenant
    case OUTSIDE_TENANT = 'outside_tenant';

    // The complete set could not be read; the default answer
    case UNKNOWN = 'unknown';

    /**
     * Whether every principal is known to be a membership of the tenant.
     *
     * @return bool
     */
    public function isWithinTenant(): bool
    {
        return $this === self::WITHIN_TENANT;
    }
}
