<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs\Enums;

/**
 * How redeeming a handoff code ended (SSO-9.2, SSO-9.9, SSO-11.8): redeemed,
 * with the verified result; refused, with a reason; or rate limited, with the
 * seconds until it may be tried again.
 *
 * The values are stable once released: a case is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RedemptionStatus: string
{
    // The code was consumed now and every check passed
    case REDEEMED = 'redeemed';

    // The redemption was refused for a reason
    case REFUSED = 'refused';

    // The redemption limit is full; the result carries `retryAfter`
    case RATE_LIMITED = 'rate_limited';
}
