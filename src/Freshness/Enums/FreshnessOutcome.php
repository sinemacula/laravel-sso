<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Freshness\Enums;

/**
 * Whether the caller's authentication is recent enough for an operation.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FreshnessOutcome: string
{
    // The caller authenticated within the operation's maximum age
    case FRESH = 'fresh';

    // The caller did not, or cannot be judged; the operation is refused
    case STALE = 'stale';

    /**
     * Whether the operation may go ahead.
     *
     * @return bool
     */
    public function isFresh(): bool
    {
        return $this === self::FRESH;
    }
}
