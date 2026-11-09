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
 * Whether a purpose may start through a usable connection (steps 6 and 7 of a
 * start, `AuthorizationRequestService`): a `sign_in` always may; a `link` once
 * the freshness contract answers `fresh` for `sso.link.create` (SSO-2.12) for
 * the caller, with the session it gave, else `freshness_required`; a
 * `reauthenticate` once `Contracts\ReauthenticationSessions::standing()`
 * answers the caller's identity signed in through the connection on its session
 * (SSO-5.10), else `session_ineligible`. That alone, since the exact link is
 * judged at redemption, under the session's lock.
 *
 * It holds the freshness gate and the session contract, neither of which keeps
 * anything of one start for the next (SSO-11.2).
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

        /** Whether the identity of a `reauthenticate` is signed in on its session. */
        private ReauthenticationSessions $sessions,
    ) {}

    /**
     * Why the purpose may not start through the connection, for the caller, or
     * `null` when it may.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function refusal(Purpose $purpose, Connection $connection, ?Caller $caller): ?FailureReason
    {
        return match ($purpose) {
            Purpose::SIGN_IN        => null,
            Purpose::LINK           => $this->freshness->check(FreshnessOperation::LINK_CREATE, $caller)->isFresh() ? null : FailureReason::FRESHNESS_REQUIRED,
            Purpose::REAUTHENTICATE => $this->isSignedIn($connection, $caller) ? null : FailureReason::SESSION_INELIGIBLE,
        };
    }

    /**
     * Whether the caller's identity is signed in through the connection on its
     * session. Only a `reauthenticate` asks, whose caller gives both.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return bool
     */
    private function isSignedIn(Connection $connection, ?Caller $caller): bool
    {
        assert($caller !== null && $caller->sessionId !== null);

        return $this->sessions->standing($caller->identity, $caller->sessionId, $connection)->isSignedIn();
    }
}
