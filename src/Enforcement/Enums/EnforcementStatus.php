<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement\Enums;

/**
 * How a change to a tenant's enforcement ended.
 *
 * Stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum EnforcementStatus: string
{
    // Written with a new version, revoked as needed and reported
    case UPDATED = 'updated';

    // Already held what was given; nothing was written or reported
    case UNCHANGED = 'unchanged';

    // The change was refused; the result carries the reason
    case REFUSED = 'refused';

    // The connection ids given were refused; the result carries the violations
    case INVALID = 'invalid';

    /**
     * Whether the status names a success, a change made or not.
     *
     * @return bool
     */
    public function isSucceeded(): bool
    {
        return $this === self::UPDATED || $this === self::UNCHANGED;
    }
}
