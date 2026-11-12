<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows\Enums;

/**
 * How consuming the authorisation request a response answers ended; only
 * `consumed` lets a completion go on.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ConsumptionStatus: string
{
    // The request was consumed now and the response may be validated
    case CONSUMED = 'consumed';

    // The request was consumed now but the response may not go on
    case REFUSED = 'refused';

    // No request matches the response
    case UNKNOWN = 'unknown';

    // The request was consumed before: a replay
    case REPLAYED = 'replayed';
}
