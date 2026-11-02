<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Linking;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * A reauthentication session contract with one session, bound to the link the
 * test sets, recording each renewal it was asked for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingSessions implements ReauthenticationSessions
{
    /** @var list<array{0: string, 1: \Carbon\CarbonImmutable, 2: ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence}> Every renewal: the session, the time and the evidence. */
    public array $renewed = [];

    /**
     * Constructor.
     *
     * @param  ?string  $boundLink
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding  $standing
     */
    public function __construct(

        /** The link the session is bound to. */
        public ?string $boundLink = null,

        /** What it answers. */
        public SessionStanding $standing = SessionStanding::SIGNED_IN,
    ) {}

    /**
     * Answer the standing set.
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

        return $this->standing;
    }

    /**
     * Answer the standing set, when the session is bound to exactly the link.
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
        unset($identity, $sessionId, $application, $connection);

        return $this->boundLink === $linkId ? $this->standing : SessionStanding::NOT_SIGNED_IN;
    }

    /**
     * Record the renewal.
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
        unset($identity);

        $this->renewed[] = [$sessionId, $authenticatedAt, $evidence];
    }

    /**
     * How many renewals it was asked for.
     *
     * @return int
     */
    public function renewals(): int
    {
        return count($this->renewed);
    }
}
