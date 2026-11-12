<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs\Enums;

/**
 * How redeeming a handoff code ended.
 *
 * Values are stable: a case is never renamed or reused.
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
