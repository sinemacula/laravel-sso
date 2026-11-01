<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The default reauthentication session contract (SSO-5.10): the package keeps
 * no sessions, so no identity is ever signed in through a connection on one,
 * and no `reauthenticate` flow starts until the application binds its own.
 *
 * It holds nothing between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NoReauthenticationSessions implements ReauthenticationSessions
{
    /**
     * Nobody is signed in on any session.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
     */
    #[\Override]
    public function standing(IdentityReference $identity, string $sessionId, SsoConnection $connection): SessionStanding
    {
        unset($identity, $sessionId, $connection);

        return SessionStanding::NOT_SIGNED_IN;
    }
}
