<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Discovery;

use SineMacula\Laravel\Sso\Flows\FlowSettings;

/**
 * Holds a discovery answer until the configured minimum duration has passed
 * since the start, measured on the monotonic clock, not `Contracts\Clock`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Pacer
{
    /** @var int Nanoseconds in a microsecond. */
    private const int NANOSECONDS_PER_MICROSECOND = 1000;

    /** @var int Microseconds in a millisecond. */
    private const int MICROSECONDS_PER_MILLISECOND = 1000;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\FlowSettings  $settings
     */
    public function __construct(

        /** The least time a discovery start takes. */
        private FlowSettings $settings,
    ) {}

    /**
     * The instant an answer starts, in nanoseconds, once the floor is known to
     * be well formed.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function start(): int
    {
        // Read now, so a malformed floor fails before any work, not after it
        $this->floor();

        return self::now();
    }

    /**
     * Wait until the floor has passed since the answer started, again after a
     * sleep that ends early.
     *
     * @param  int  $startedAt
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function finish(int $startedAt): void
    {
        $floor = $this->floor();

        for ($remaining = self::remainingOf($startedAt, $floor); $remaining !== 0; $remaining = self::remainingOf($startedAt, $floor)) {
            usleep($remaining);
        }
    }

    /**
     * The microseconds left until the floor has passed, never negative.
     *
     * @param  int  $startedAt
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function remaining(int $startedAt): int
    {
        return self::remainingOf($startedAt, $this->floor());
    }

    /**
     * The floor, in microseconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function floor(): int
    {
        return $this->settings->discoveryMinimumDurationMilliseconds() * self::MICROSECONDS_PER_MILLISECOND;
    }

    /**
     * The microseconds left of the floor, never negative; elapsed time rounds
     * down so the wait never ends before the floor.
     *
     * @param  int  $startedAt
     * @param  int  $floor
     * @return int
     */
    private static function remainingOf(int $startedAt, int $floor): int
    {
        $elapsed = intdiv(self::now() - $startedAt, self::NANOSECONDS_PER_MICROSECOND);

        return max(0, $floor - $elapsed);
    }

    /**
     * The monotonic clock's instant, in nanoseconds.
     *
     * @return int
     */
    private static function now(): int
    {
        return (int) hrtime(true);
    }
}
