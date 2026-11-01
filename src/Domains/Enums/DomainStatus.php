<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains\Enums;

/**
 * How a domain operation ended (SSO-3.1, SSO-3.2, SSO-2.11): the status of a
 * `Domains\DomainResult`. Three name a change made, one per operation;
 * `unchanged` a success that wrote nothing; `refused` and `invalid` a change
 * not made, with nothing written and nothing reported.
 *
 * Backed, and stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum DomainStatus: string
{
    // The domain was claimed for the connection, pending, with a new token
    case CLAIMED = 'claimed';

    // Its record carried the token, and the domain is now verified for the
    // connection
    case VERIFIED = 'verified';

    // The domain was verified already; nothing was looked up or written
    case UNCHANGED = 'unchanged';

    // The claim was removed, whatever its state
    case REMOVED = 'removed';

    // The change was refused; the result carries the reason, and the seconds to
    // wait when it was rate limited
    case REFUSED = 'refused';

    // The domain given was refused; the result carries the violations
    case INVALID = 'invalid';

    /**
     * Whether the status names a success, a change made or not.
     *
     * @return bool
     */
    public function isSucceeded(): bool
    {
        return $this !== self::REFUSED && $this !== self::INVALID;
    }
}
