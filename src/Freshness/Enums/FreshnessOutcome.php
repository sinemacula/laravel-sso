<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Freshness\Enums;

/**
 * What the freshness contract answered for an operation (SSO-2.12): the
 * caller's authentication is recent enough for the operation's maximum age, or
 * it is not and the operation is refused.
 *
 * Only `fresh` lets the operation write. A helper refused by `stale` answers
 * `FailureReason::FRESHNESS_REQUIRED`, so the application can ask the caller to
 * authenticate again and retry.
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

    // The caller did not, or there is no caller the contract can judge: the
    // operation is refused
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
