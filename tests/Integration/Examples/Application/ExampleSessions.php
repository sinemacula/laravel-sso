<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Application;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The example application's in-memory reauthentication sessions, each bound to
 * its identity, application, connection and link.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExampleSessions implements ReauthenticationSessions
{
    /** @var array<string, array{identity: \SineMacula\Laravel\Sso\Identities\IdentityReference, application: string, connection: string, link: string, authenticated_at: \Carbon\CarbonImmutable}> Each session, by its id. */
    private array $sessions = [];

    /**
     * Write the session a `sign_in` establishes.
     *
     * @param  string  $sessionId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $application
     * @param  string  $connectionId
     * @param  string  $linkId
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @return void
     */
    public function establish(string $sessionId, IdentityReference $identity, string $application, string $connectionId, string $linkId, CarbonImmutable $authenticatedAt): void
    {
        $this->sessions[$sessionId] = [
            'identity'         => $identity,
            'application'      => $application,
            'connection'       => $connectionId,
            'link'             => $linkId,
            'authenticated_at' => $authenticatedAt,
        ];
    }

    /**
     * When the session last authenticated, or `null` when there is no such
     * session.
     *
     * @param  string  $sessionId
     * @return ?\Carbon\CarbonImmutable
     */
    public function authenticatedAt(string $sessionId): ?CarbonImmutable
    {
        return isset($this->sessions[$sessionId]) ? $this->sessions[$sessionId]['authenticated_at'] : null;
    }

    /**
     * Whether the identity is signed in on the session, of the application,
     * through the connection.
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
        $held = $this->holds($sessionId, $identity, $connection) && $this->sessions[$sessionId]['application'] === $application;

        return $held ? SessionStanding::SIGNED_IN : SessionStanding::NOT_SIGNED_IN;
    }

    /**
     * Whether the identity is signed in on the session, of the application,
     * through the connection and exactly the link.
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
        $session = $this->sessions[$sessionId] ?? null;

        if ($session === null || !$this->holds($sessionId, $identity, $connection)) {
            return SessionStanding::NOT_SIGNED_IN;
        }

        return $session['application'] === $application && $session['link'] === $linkId ? SessionStanding::SIGNED_IN : SessionStanding::NOT_SIGNED_IN;
    }

    /**
     * Renew the session's authentication time, never moving it backwards.
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
        unset($identity, $evidence);

        $current = $this->authenticatedAt($sessionId);

        if ($current === null) {
            return;
        }

        $this->sessions[$sessionId]['authenticated_at'] = $current->greaterThan($authenticatedAt) ? $current : $authenticatedAt;
    }

    /**
     * Whether the session exists and holds the identity, signed in through the
     * connection.
     *
     * @param  string  $sessionId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return bool
     */
    private function holds(string $sessionId, IdentityReference $identity, SsoConnection $connection): bool
    {
        $session = $this->sessions[$sessionId] ?? null;

        return $session !== null && $session['identity']->is($identity) && $session['connection'] === $connection->getConnectionId();
    }
}
