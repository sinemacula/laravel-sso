<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\RateLimiting;

use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;

/**
 * The default attempt limiter (SSO-11.8): per flow, one counter for each scope
 * the attempt is counted in, kept in the rate limits table on the counters'
 * connection, so the limits hold across servers without a cache.
 *
 * A counter's key is a keyed digest of the flow, the scope and the value in its
 * canonical form (see `CounterKeys`), so the table gives back no IP address,
 * email domain or connection id. A value the subject does not give (a `null` IP
 * address or email domain) is not counted.
 *
 * Every attempt counts, all or none: a slot is taken from each counter in turn,
 * in the order of the flow's scopes, and when one is full every slot taken
 * before it is given back, to the window it was taken from, and the attempt is
 * refused with the seconds until the full counter's window ends. Counts change
 * only through single statements (see `RateLimitStore`), so concurrent attempts
 * never exceed a limit and giving a slot back never touches a later window.
 *
 * The limits are read on every attempt and are always on: a missing or
 * malformed one fails closed (see `AttemptLimits`). Database errors propagate:
 * a limiter that cannot count does not let attempts through. Every time is read
 * from the one bindable clock (SSO-11.13). The limiter holds nothing between
 * calls, and is bound scoped (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DatabaseAttemptLimiter implements AttemptLimiter
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptLimits  $limits
     * @param  \SineMacula\Laravel\Sso\RateLimiting\RateLimitStore  $store
     * @param  \SineMacula\Laravel\Sso\RateLimiting\CounterKeys  $keys
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The limits on each flow. */
        private AttemptLimits $limits,

        /** The counters. */
        private RateLimitStore $store,

        /** The keys the counters are stored under. */
        private CounterKeys $keys,

        /** The clock the windows are read from. */
        private Clock $clock,
    ) {}

    /**
     * Take a slot from each counter the subject counts against, in the order of
     * its flow's scopes. When one is full, every slot taken before it is given
     * back, and the wait is until the full counter's window, as stored, ends.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject  $subject
     * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptResult
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     */
    #[\Override]
    public function attempt(AttemptSubject $subject): AttemptResult
    {
        $limits  = $this->limits->for($subject->flow);
        $now     = $this->clock->now()->getTimestamp();
        $windows = [];

        foreach ($this->counters($subject, $limits) as $key => $limit) {

            $window = $this->store->take($key, $limit->max, $now, $limit->windowEnd($now));

            if (is_int($window)) {

                $this->giveBack($windows);

                return AttemptResult::rateLimited(max(1, $window - $now));
            }

            $windows[$key] = $window;
        }

        return AttemptResult::allowed();
    }

    /**
     * The counters the subject's attempt counts against, by key, with their
     * limits, in the order of its flow's scopes.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject  $subject
     * @param  array<string, \SineMacula\Laravel\Sso\RateLimiting\AttemptLimit>  $limits
     * @return array<string, \SineMacula\Laravel\Sso\RateLimiting\AttemptLimit>
     *
     * @throws \InvalidArgumentException
     */
    private function counters(AttemptSubject $subject, array $limits): array
    {
        $counted  = $subject->counted();
        $counters = [];

        foreach ($subject->flow->scopes() as $scope) {

            if (!array_key_exists($scope->value, $counted)) {
                continue;
            }

            $counters[$this->keys->counter($subject->flow, $scope, $counted[$scope->value])] = $limits[$scope->value];
        }

        return $counters;
    }

    /**
     * Give back the slots taken, each to its own window.
     *
     * @param  array<string, string>  $windows
     * @return void
     */
    private function giveBack(array $windows): void
    {
        foreach ($windows as $key => $window) {
            $this->store->giveBack($key, $window);
        }
    }
}
