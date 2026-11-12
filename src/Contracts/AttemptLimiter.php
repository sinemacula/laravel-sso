<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;

/**
 * Limits how often each IP address, email domain and connection may try a flow,
 * with a count every server shares.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AttemptLimiter
{
    /**
     * Count against every limit or none; a store error propagates rather than
     * letting the attempt through.
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
