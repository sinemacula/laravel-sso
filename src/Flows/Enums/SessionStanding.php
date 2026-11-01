<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows\Enums;

/**
 * What the reauthentication contract answered for an identity, a session and a
 * connection (SSO-5.10, SSO-9.9): whether the identity is signed in through the
 * connection on that session, still active.
 *
 * Only `signed_in` lets a `reauthenticate` flow start, or a `reauthenticate`
 * handoff be redeemed; every other answer refuses with `session_ineligible`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum SessionStanding: string
{
    // The identity is signed in through the connection on the session, which is
    // active
    case SIGNED_IN = 'signed_in';

    // It is not, or the contract cannot tell; the default answer
    case NOT_SIGNED_IN = 'not_signed_in';

    /**
     * Whether the identity is signed in through the connection on the session.
     *
     * @return bool
     */
    public function isSignedIn(): bool
    {
        return $this === self::SIGNED_IN;
    }
}
