<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Reauthenticating;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The example application's re-authentication contract (SSO-5.10, SSO-9.5),
 * over its own `Session` model on the package's storage connection: a start
 * reads the session without a lock; a redemption reads it with a locking read,
 * in the redemption's transaction, and accepts only the exact application and
 * link that established it; and a renewal writes the later of the session's
 * authentication time and the provider's on that locked row, so it never moves
 * backwards. The application keeps no further-factor evidence, so the evidence
 * a renewal is given is not written.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class UserSessions implements ReauthenticationSessions
{
    /**
     * Whether the identity is signed in on the session, of the application,
     * through the connection, read without a lock.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
     */
    #[\Override]
    public function standing(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection): SessionStanding
    {
        $session = Session::on(StorageConnection::name())->useWritePdo()->whereKey($sessionId)->whereNull('revoked_at')->first();
        $held    = [$session?->identity_type, $session?->identity_id, $session?->application, $session?->connection_id];

        return $held === [$identity->type, $identity->id, $application, $connection->getConnectionId()] ? SessionStanding::SIGNED_IN : SessionStanding::NOT_SIGNED_IN;
    }

    // @snippet-start reauthenticating-locked-standing
    /**
     * Whether the identity is signed in on the session, of the application,
     * through the connection and exactly the link, with the session's row
     * locked until the redemption's transaction ends.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  string  $linkId
     * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
     */
    #[\Override]
    public function lockedStanding(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection, string $linkId): SessionStanding
    {
        $session = Session::on(StorageConnection::name())
            ->useWritePdo()
            ->lockForUpdate()
            ->whereKey($sessionId)
            ->first();

        // Gone or revoked
        if ($session === null || $session->revoked_at !== null) {
            return SessionStanding::NOT_SIGNED_IN;
        }

        // Only its identity, application, connection and exact link
        $held     = [$session->identity_type, $session->identity_id, $session->application, $session->connection_id, $session->sso_link_id];
        $expected = [$identity->type, $identity->id, $application, $connection->getConnectionId(), $linkId];

        return $held === $expected ? SessionStanding::SIGNED_IN : SessionStanding::NOT_SIGNED_IN;
    }
    // @snippet-end reauthenticating-locked-standing

    /**
     * Renew the session's authentication time on its locked row, never moving
     * it backwards.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
     * @return void
     */
    #[\Override]
    public function renewAuthentication(IdentityReference $identity, string $sessionId, CarbonImmutable $authenticatedAt, ?AcceptedEvidence $evidence): void
    {
        // lockedStanding() matched the identity; no evidence is kept
        unset($identity, $evidence);

        $session = Session::on(StorageConnection::name())->useWritePdo()->lockForUpdate()->whereKey($sessionId)->firstOrFail();

        // A later time, from another flow redeemed first, stays
        if ($session->authenticated_at?->greaterThanOrEqualTo($authenticatedAt) === true) {
            return;
        }

        $session->authenticated_at = $authenticatedAt;
        $session->save();
    }
}
