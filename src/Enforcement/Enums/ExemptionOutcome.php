<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement\Enums;

/**
 * Whether an identity is exempt from an enforcing tenant's enforcement.
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

    // The default answer for everyone
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
