<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking\Enums;

/**
 * Whether an identity may link through a connection.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum LinkEligibilityVerdict: string
{
    // The identity may link through the connection
    case ELIGIBLE = 'eligible';

    // It may not, or the contract cannot tell; the default answer
    case INELIGIBLE = 'ineligible';

    /**
     * Whether the identity may link.
     *
     * @return bool
     */
    public function isEligible(): bool
    {
        return $this === self::ELIGIBLE;
    }
}
