<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Whether a purpose may start through a usable connection (steps 6 and 7 of a
 * start, `AuthorizationRequestService`): a `sign_in` always may; a `link` once
 * the freshness contract answers `fresh` for `sso.link.create` (SSO-2.12), else
 * `freshness_required`; a `reauthenticate` once
 * `Contracts\ReauthenticationSessions::standing()` answers the identity signed
 * in through the connection on the session (SSO-5.10), else
 * `session_ineligible`. That alone, since the exact link is judged at
 * redemption, under the session's lock.
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
     * Why the purpose may not start through the connection, for the identity
     * and on the session its binding names, or `null` when it may.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function refusal(Purpose $purpose, Connection $connection, ?IdentityReference $identity, ?string $sessionId): ?FailureReason
    {
        return match ($purpose) {
            Purpose::SIGN_IN        => null,
            Purpose::LINK           => $this->freshness->check(FreshnessOperation::LINK_CREATE)->isFresh() ? null : FailureReason::FRESHNESS_REQUIRED,
            Purpose::REAUTHENTICATE => $this->isSignedIn($connection, $identity, $sessionId) ? null : FailureReason::SESSION_INELIGIBLE,
        };
    }

    /**
     * Whether the identity is signed in through the connection on the session.
     * Only a `reauthenticate` asks, whose binding gives both.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return bool
     */
    private function isSignedIn(Connection $connection, ?IdentityReference $identity, ?string $sessionId): bool
    {
        assert($identity !== null && $sessionId !== null);

        return $this->sessions->standing($identity, $sessionId, $connection)->isSignedIn();
    }
}
