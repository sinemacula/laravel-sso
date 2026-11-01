<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows\Enums;

/**
 * What a flow is started for (SSO-5.1): signing in, linking the subject to an
 * identity the application has already authenticated, or renewing the freshness
 * of a session established through the connection. The value is the purpose an
 * event's context carries and a handoff code is bound to.
 *
 * Backed, and stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Purpose: string
{
    // Sign in through the connection (SSO-5.1, SSO-9.9)
    case SIGN_IN = 'sign_in';

    // Link the provider's subject to an identity the application has
    // authenticated, with fresh authentication; creates no session (SSO-5.11)
    case LINK = 'link';

    // Renew the freshness of a session established through the connection,
    // forcing fresh authentication at the identity provider (SSO-5.10)
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
}
