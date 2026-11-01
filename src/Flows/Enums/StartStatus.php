<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows\Enums;

/**
 * How a start of an authorisation request ended (SSO-5.1, SSO-3.4): started,
 * with a reference and a navigation; refused, with a reason; or rate limited,
 * with the seconds until it may be tried again (SSO-11.8).
 *
 * A discovery miss, and a start naming an unknown or disabled connection for an
 * application that offers discovery, are `started`: they lead to the
 * application's fallback, answered in the same shape as a match (SSO-3.5).
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
