<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement\Enums;

/**
 * How a change to a tenant's enforcement ended (SSO-4.1, SSO-4.3, SSO-4.5,
 * SSO-2.11): the status of an `Enforcement\EnforcementResult`. `updated` names
 * a change made; `unchanged` a success that wrote nothing; `refused` and
 * `invalid` a change not made, with nothing written, revoked or reported.
 *
 * Backed, and stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum EnforcementStatus: string
{
    // The tenant's enforcement was written with a new version, any revocation
    // it needed ran, and the change was reported
    case UPDATED = 'updated';

    // The tenant's enforcement already held what was given; nothing was asked,
    // written or reported
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
