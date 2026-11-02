<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Reauthentication session contract (SSO-5.10, SSO-9.5, SSO-9.9): whether an
 * identity is signed in through a connection on a session of the application's,
 * still active, which a `reauthenticate` flow needs when it starts, and the two
 * operations its redemption makes inside the redeemer's transaction.
 *
 * `standing()` answers from current state when the flow starts, and locks
 * nothing: the exact link is not known yet, so it is judged at redemption.
 * `lockedStanding()` is asked inside the redeemer's transaction on the
 * package's storage connection (decision D5): the identity, the session, the
 * application and the connection must all match, the session's bound link must
 * be exactly the link given (the one link that established the session, never
 * another link of that identity), and an implementation locks the session's row
 * with a locking read on that same Laravel connection, so logout, revocation or
 * the replacement of its binding waits for that transaction: a check followed
 * by an unprotected write would race them. `renewAuthentication()` then renews
 * the session's authentication time, in that same transaction, and stores the
 * evidence given, if any; it extends no lifetime, issues no refresh token,
 * rewrites no sign-in provenance and refreshes no earlier evidence (SSO-9.5).
 * `null` evidence means nothing new was accepted, and leaves what the session
 * holds as it is. Link suspension blocks reauthentication before either is
 * asked.
 *
 * The session's bound link is recorded when the session is written, from
 * `Handoffs\RedemptionResult::$linkId`, inside the transaction of the sign-in's
 * `Handoffs\HandoffRedemption::admit()`, and only a change that replaces the
 * credential may rewrite it. A session with no bound link (one from an unlinked
 * handoff) is `not_signed_in` to `lockedStanding()`, whatever link is given.
 *
 * Lock order: the package holds its own locks (`docs/design/linking.md`) before
 * it asks `lockedStanding()`, so the session's row comes after the links. A
 * writer that locks a session's row takes no package lock after it: a logout
 * locks the row alone, and a revocation through `Contracts\SessionRevocation`
 * already holds the connection's lock when it is called.
 *
 * The package keeps no sessions, so the default,
 * `Flows\NoReauthenticationSessions`, answers `not_signed_in` for every
 * question, and no `reauthenticate` flow starts until the application binds its
 * own. Under `laravel-iam` it is bound to `laravel-authentication`'s sessions,
 * read from their external-provider provenance (SSO-9.10). An implementation
 * reads from the write connection where it reads the package's database, keeps
 * nothing of one call for the next (SSO-11.2), and never answers `signed_in`
 * when it cannot tell; an error it cannot answer through propagates and rolls
 * the redemption back, its consumption included. See
 * `docs/guides/reauthenticating.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ReauthenticationSessions
{
    /**
     * Whether the identity is signed in through the connection on the session,
     * when a flow starts. It locks nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
     */
    public function standing(IdentityReference $identity, string $sessionId, SsoConnection $connection): SessionStanding;

    /**
     * Whether the identity is signed in on the session, of the application,
     * through the connection and exactly the link, with the session's row
     * locked until the redeemer's transaction ends.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  string  $linkId
     * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
     */
    public function lockedStanding(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection, string $linkId): SessionStanding;

    /**
     * Renew the session's authentication time, and nothing else but storing the
     * evidence accepted from this authentication, inside the redeemer's
     * transaction, on the row `lockedStanding()` locked. A later time the
     * session holds already is kept: a renewal never moves it backwards.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
     * @return void
     */
    public function renewAuthentication(IdentityReference $identity, string $sessionId, CarbonImmutable $authenticatedAt, ?AcceptedEvidence $evidence): void;
}
