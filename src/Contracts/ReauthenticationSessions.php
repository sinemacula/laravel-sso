<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Reauthentication session contract (SSO-5.10, SSO-9.5, SSO-9.9): whether an
 * identity is signed in through a connection on a session of the application's,
 * still active, which a `reauthenticate` flow needs when it starts and when its
 * handoff is redeemed.
 *
 * The package keeps no sessions, so the default,
 * `Flows\NoReauthenticationSessions`, answers `not_signed_in` for every
 * question, and no `reauthenticate` flow starts until the application binds its
 * own. Under `laravel-iam` it is bound to `laravel-authentication`'s sessions,
 * read from their external-provider provenance (SSO-9.10). An implementation
 * answers from current state on each call, reads from the write connection
 * where it reads the package's database, keeps nothing of one call for the next
 * (SSO-11.2), and never answers `signed_in` when it cannot tell; an error it
 * cannot answer through propagates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ReauthenticationSessions
{
    /**
     * Whether the identity is signed in through the connection on the session.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
     */
    public function standing(IdentityReference $identity, string $sessionId, SsoConnection $connection): SessionStanding;
}
