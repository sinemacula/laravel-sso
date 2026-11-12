<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains\Enums;

/**
 * How a domain operation ended, as the status of a `Domains\DomainResult`.
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

    // Its record carried the token; the domain is verified for the connection
    case VERIFIED = 'verified';

    // The domain was verified already; nothing was looked up or written
    case UNCHANGED = 'unchanged';

    // The claim was removed, whatever its state
    case REMOVED = 'removed';

    // The change was refused; the result carries the reason
    case REFUSED = 'refused';

    // The domain given was refused; the result carries the violations
    case INVALID = 'invalid';

    /**
     * Whether the status names a success, whether or not it wrote anything.
     *
     * @return bool
     */
    public function isSucceeded(): bool
    {
        return $this !== self::REFUSED && $this !== self::INVALID;
    }
}
