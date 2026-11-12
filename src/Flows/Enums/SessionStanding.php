<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows\Enums;

/**
 * Whether an identity is signed in on a session; only `signed_in` lets a
 * `reauthenticate` start or redeem.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum SessionStanding: string
{
    // Signed in through the connection on the application's active session
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
