<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The application's sessions as a `reauthenticate` flow and its redemption see
 * them.
 *
 * Never answer `signed_in` when unsure; see `docs/guides/reauthenticating.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ReauthenticationSessions
{
    /**
     * Whether the identity is signed in on the session when a flow starts, for
     * the application the flow is started for; lock nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
     */
    public function standing(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection): SessionStanding;

    /**
     * Match the session's bound link exactly, and lock its row by a locking
     * read on the storage connection until the redeemer's transaction ends.
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
     * Renew the authentication time as `max(current, provider_time)` and store
     * any evidence given, on the row `lockedStanding()` locked.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
     * @return void
     */
    public function renewAuthentication(IdentityReference $identity, string $sessionId, CarbonImmutable $authenticatedAt, ?AcceptedEvidence $evidence): void;
}
