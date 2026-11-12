<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows\Enums;

/**
 * How a start of an authorisation request ended; a discovery fallback is
 * `started`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum StartStatus: string
{
    // The client is sent on, with the request's public reference
    case STARTED = 'started';

    // The start was refused for a reason
    case REFUSED = 'refused';

    // A limit is full; the result carries `retryAfter`
    case RATE_LIMITED = 'rate_limited';
}
