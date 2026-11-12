<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Whether a purpose may start: freshness for a `link`, a signed-in session for
 * a `reauthenticate`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StartEligibility
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\FreshnessGate  $freshness
     * @param  \SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions  $sessions
     */
    public function __construct(

        /** Asks the freshness contract before a `link` starts. */
        private FreshnessGate $freshness,

        /** Whether a `reauthenticate` caller is signed in on its session. */
        private ReauthenticationSessions $sessions,
    ) {}

    /**
     * Why the purpose may not start, or `null` when it may.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function refusal(string $application, Purpose $purpose, Connection $connection, ?Caller $caller): ?FailureReason
    {
        return match ($purpose) {
            Purpose::SIGN_IN        => null,
            Purpose::LINK           => $this->freshness->check(FreshnessOperation::LINK_CREATE, $caller)->isFresh() ? null : FailureReason::FRESHNESS_REQUIRED,
            Purpose::REAUTHENTICATE => $this->isSignedIn($application, $connection, $caller) ? null : FailureReason::SESSION_INELIGIBLE,
        };
    }

    /**
     * Whether the caller is signed in on its session, of the application,
     * through the connection; the exact link is judged at redemption.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return bool
     */
    private function isSignedIn(string $application, Connection $connection, ?Caller $caller): bool
    {
        assert($caller !== null && $caller->sessionId !== null);

        return $this->sessions->standing($caller->identity, $caller->sessionId, $application, $connection)->isSignedIn();
    }
}
