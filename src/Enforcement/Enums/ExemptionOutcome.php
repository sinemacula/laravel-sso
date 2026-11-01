<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement\Enums;

/**
 * What the exemption contract answered for an identity in an enforcing tenant
 * (SSO-4.4): exempt from the tenant's enforcement, or not.
 *
 * Only `exempt` lets a session be established in an enforcing tenant other than
 * through a connection that satisfies it, and its use is reported
 * (`Events\ExemptionUsed`).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ExemptionOutcome: string
{
    // The identity may be signed in without a satisfying connection
    case EXEMPT = 'exempt';

    // It may not; the default answer for everyone
    case NOT_EXEMPT = 'not_exempt';

    /**
     * Whether the identity is exempt.
     *
     * @return bool
     */
    public function isExempt(): bool
    {
        return $this === self::EXEMPT;
    }
}
