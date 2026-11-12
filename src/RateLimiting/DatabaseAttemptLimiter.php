<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\RateLimiting;

use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;

/**
 * Default attempt limiter: database counters, one per scope, so limits hold
 * across servers; an attempt counts against all of them or none.
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
     * Take a slot from each counter, giving back those taken if one is full.
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
     * The subject's counter keys with their limits, in scope order.
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
