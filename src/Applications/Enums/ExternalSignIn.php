<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Applications\Enums;

/**
 * Whether the application policy allows an application external sign-in.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ExternalSignIn: string
{
    // The application allows sign-in through an external provider
    case ALLOWED = 'allowed';

    // It does not; the default
    case NOT_ALLOWED = 'not_allowed';

    /**
     * Whether external sign-in is allowed.
     *
     * @return bool
     */
    public function isAllowed(): bool
    {
        return $this === self::ALLOWED;
    }
}
