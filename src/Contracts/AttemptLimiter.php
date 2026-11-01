<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;

/**
 * Attempt limiter contract (SSO-11.8): limits how often each IP address, email
 * domain and connection may try each flow the package limits, counted where
 * every server sees the same count, so the limits hold across servers and
 * without a cache.
 *
 * Every attempt counts, whether it then succeeds or fails, against every limit
 * its subject names, all or none: when one is full, nothing is counted and the
 * attempt is refused with the seconds until the full limit's window ends. The
 * limits are always on; the configuration sets their sizes. A limiter that
 * cannot count does not let attempts through: a store error propagates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AttemptLimiter
{
    /**
     * Count the attempt against each limit its subject names, or refuse it. A
     * limit whose configuration is malformed fails closed with an
     * `InvalidArgumentException`.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject  $subject
     * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptResult
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     */
    public function attempt(AttemptSubject $subject): AttemptResult;
}
