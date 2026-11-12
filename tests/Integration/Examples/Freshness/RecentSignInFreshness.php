<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Freshness;

use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;

/**
 * The example application's freshness contract: a recent sign-in on the
 * caller's own session is fresh.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecentSignInFreshness implements Freshness
{
    // @snippet-start recent-sign-in-freshness
    /**
     * Take the application's record of sign-ins and the package's clock.
     *
     * @param  \Tests\Integration\Examples\Freshness\SignInTimes  $signIns
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** When each session last authenticated, as the sign-in recorded it. */
        private SignInTimes $signIns,

        /** The package's clock, which a test can move. */
        private Clock $clock,
    ) {}

    /**
     * Whether the caller authenticated within the maximum age.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  int  $maxAgeSeconds
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
     */
    #[\Override]
    public function check(FreshnessOperation $operation, int $maxAgeSeconds, ?Caller $caller): FreshnessOutcome
    {
        // Every operation is judged alike: a stricter policy would match on
        // the operation's stable name, $operation->value
        unset($operation);

        // No caller, or one on no session, cannot be judged
        if ($caller?->sessionId === null) {
            return FreshnessOutcome::STALE;
        }

        // The caller's own session, never the request being served
        $authenticatedAt = $this->signIns->authenticatedAt($caller->identity, $caller->sessionId);

        if ($authenticatedAt === null) {
            return FreshnessOutcome::STALE;
        }

        $age = $this->clock->now()->getTimestamp() - $authenticatedAt;

        return $age >= 0 && $age <= $maxAgeSeconds ? FreshnessOutcome::FRESH : FreshnessOutcome::STALE;
    }
    // @snippet-end recent-sign-in-freshness
}
