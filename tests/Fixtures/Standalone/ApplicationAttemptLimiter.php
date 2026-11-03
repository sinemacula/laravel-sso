<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Standalone;

use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;

/**
 * An application's attempt limiter: it counts every attempt itself, as one kept
 * in the application's own store would, with no row in the package's counters.
 * Past the attempts it allows, each attempt is refused with the wait it was
 * given; with none set, it allows them all.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApplicationAttemptLimiter implements AttemptLimiter
{
    /** @var list<\SineMacula\Laravel\Sso\RateLimiting\AttemptSubject> Every attempt, in order. */
    public array $subjects = [];

    /**
     * Constructor.
     *
     * @param  ?int  $allowing
     * @param  int  $retryAfter
     */
    public function __construct(

        /** How many attempts in all it allows; none set is every one. */
        public ?int $allowing = null,

        /** The wait a refused attempt is told of, in seconds. */
        public int $retryAfter = 30,
    ) {}

    /**
     * Count the attempt, and refuse it past what is allowed.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject  $subject
     * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptResult
     */
    #[\Override]
    public function attempt(AttemptSubject $subject): AttemptResult
    {
        $this->subjects[] = $subject;

        return $this->allowing !== null && count($this->subjects) > $this->allowing ? AttemptResult::rateLimited($this->retryAfter) : AttemptResult::allowed();
    }
}
