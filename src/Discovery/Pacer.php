<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Discovery;

use SineMacula\Laravel\Sso\Flows\FlowSettings;

/**
 * Makes a discovery start answer no earlier than the least time it takes,
 * `FlowSettings::discoveryMinimumDurationMilliseconds()` (50 to 2000, default
 * 250), after it started, so a match and a miss answer in the same time
 * whatever work each did (SSO-3.5).
 *
 * The time is measured on the monotonic clock (`hrtime()`), in nanoseconds, and
 * waited out with `usleep()`, again until the floor is reached, since a sleep
 * may end early. It is not the package's `Contracts\Clock`, which a test may
 * freeze and which tells the time of day rather than how long something took.
 * The time remaining is never negative: an answer that already took longer than
 * the floor is not delayed further.
 *
 * `start()` reads the floor before any work, so a malformed one fails closed
 * with an `InvalidArgumentException` naming its key before anything is counted
 * or stored; `[flows]` refuses it at boot. It keeps nothing between calls: the
 * caller holds the instant it started (SSO-11.2).
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
     * The instant an answer starts, on the monotonic clock, in nanoseconds,
     * once the floor is known to be well formed.
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
     * Wait until the floor has passed since the instant the answer started.
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
     * The microseconds left until the floor has passed since the instant the
     * answer started, and never fewer than none.
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
     * The microseconds left of the floor since the instant, never negative. The
     * time elapsed is rounded down to whole microseconds, so what is left is
     * rounded up and the wait never ends before the floor.
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
