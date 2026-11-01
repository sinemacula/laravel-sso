<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Applications\Enums;

/**
 * What the application policy answered for an application (SSO-5.1, SSO-9.2):
 * whether it allows sign-in through an external provider.
 *
 * Only `allowed` lets a flow start for the application or a handoff code be
 * issued for it; every other answer refuses with `application_not_allowed`.
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

    // It does not; the default answer for an application that does not say so
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
