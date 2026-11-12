<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\RateLimiting;

/**
 * At most `max` attempts in each epoch-aligned window of `decaySeconds`, so a
 * window's end is known without a query.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AttemptLimit
{
    /** @var int Most attempts a window may allow. */
    public const int MAX_ATTEMPTS = 1000000;

    /** @var int Longest window, in seconds (one day). */
    public const int MAX_DECAY_SECONDS = 86400;

    /**
     * Constructor.
     *
     * @param  int  $max
     * @param  int  $decaySeconds
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Attempts allowed in each window, from 1 to a million. */
        public int $max,

        /** Length of each window, in seconds, from 1 to a day. */
        public int $decaySeconds,
    ) {
        if ($max < 1 || $max > self::MAX_ATTEMPTS || $decaySeconds < 1 || $decaySeconds > self::MAX_DECAY_SECONDS) {
            $message = 'A limit needs 1 to %d attempts in a window of 1 to %d seconds, %d in %d given.';

            throw new \InvalidArgumentException(sprintf($message, self::MAX_ATTEMPTS, self::MAX_DECAY_SECONDS, $max, $decaySeconds));
        }
    }

    /**
     * The Unix time the window holding `$now` ends.
     *
     * @param  int  $now
     * @return int
     */
    public function windowEnd(int $now): int
    {
        return (intdiv($now, $this->decaySeconds) + 1) * $this->decaySeconds;
    }
}
