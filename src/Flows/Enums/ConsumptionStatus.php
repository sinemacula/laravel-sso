<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows\Enums;

/**
 * How consuming the authorisation request a response answers ended (SSO-5.1,
 * SSO-11.5): consumed, and handed to the driver to validate the response
 * against; refused once consumed, for a reason; unknown, no request matching;
 * or replayed, the request consumed before.
 *
 * Only `consumed` lets a completion go on. A request is consumed for `consumed`
 * and for `refused`, whether the response then passes or fails, and never
 * again.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ConsumptionStatus: string
{
    // The request was consumed now, and the response may be validated against
    // it
    case CONSUMED = 'consumed';

    // The request was consumed now, but the response may not go on: its
    // connection, its expiry or its SAML request id refuses it
    case REFUSED = 'refused';

    // No request matches the response
    case UNKNOWN = 'unknown';

    // The request was consumed before: a replay
    case REPLAYED = 'replayed';
}
