<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\Clock;

/**
 * A clock for the package's own tests that holds one instant until a test moves
 * it, so a test of expiry or skew does not wait and does not depend on the
 * package's default clock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FixedClock implements Clock
{
    /** @var \Carbon\CarbonImmutable The instant the clock holds. */
    private CarbonImmutable $now;

    /**
     * Constructor.
     *
     * @param  string  $now
     */
    public function __construct(string $now = '2026-10-31T12:00:00Z')
    {
        $this->now = CarbonImmutable::parse($now);
    }

    /**
     * The instant the clock holds.
     *
     * @return \Carbon\CarbonImmutable
     */
    #[\Override]
    public function now(): CarbonImmutable
    {
        return $this->now;
    }

    /**
     * Move the clock by the seconds given, backwards when negative.
     *
     * @param  int  $seconds
     * @return void
     */
    public function advance(int $seconds): void
    {
        $this->now = $this->now->addSeconds($seconds);
    }
}
