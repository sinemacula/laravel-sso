<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows\Enums;

/**
 * What a flow is started for.
 *
 * Values are stable: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Purpose: string
{
    // Sign in through the connection
    case SIGN_IN = 'sign_in';

    // Link the subject to an authenticated identity; creates no session
    case LINK = 'link';

    // Renew a session's freshness with fresh authentication at the provider
    case REAUTHENTICATE = 'reauthenticate';

    /**
     * Whether the flow must force fresh authentication at the identity provider
     * (`ForceAuthn`; `prompt=login` with `max_age=0`).
     *
     * @return bool
     */
    public function forcesAuthentication(): bool
    {
        return $this === self::REAUTHENTICATE;
    }

    /**
     * Whether the flow is bound to the caller's session; a `link` only gives
     * its session to freshness.
     *
     * @return bool
     */
    public function bindsSession(): bool
    {
        return $this === self::REAUTHENTICATE;
    }
}
