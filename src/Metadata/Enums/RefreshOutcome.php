<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata\Enums;

/**
 * How a refresh of one connection's metadata ended.
 *
 * Stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RefreshOutcome: string
{
    // Fetched, validated and applied
    case REFRESHED = 'refreshed';

    // The fetch or the metadata was refused; the last good settings are kept
    case FAILED = 'failed';

    // The connection's trust or metadata changed meanwhile; nothing was written
    case CONFLICT = 'conflict';

    // An administrator's refresh found another server's claim
    case IN_PROGRESS = 'in_progress';

    // An administrator's refresh found the connection's metadata limit full
    case RATE_LIMITED = 'rate_limited';

    // A scheduled refresh found the connection claimed or no longer due
    case SKIPPED = 'skipped';

    // An administrator's refresh was refused before anything was fetched
    case REFUSED = 'refused';
}
