<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching;

/**
 * The one deadline of a fetch (SSO-2.9): the configured timeout from the moment
 * the fetch began, shared by every lookup and every hop, redirects included.
 *
 * It is measured on a monotonic clock in nanoseconds (`hrtime(true)` in the
 * fetcher), never on `Contracts\Clock`: it measures elapsed time rather than
 * checking an instant, which a wall-clock change or Laravel's test clock would
 * move. Time is counted in whole milliseconds, and a part of one counts as
 * none, since cURL reads a timeout of `0` as no timeout at all.
 *
 * It is made for one fetch and holds nothing past it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FetchDeadline
{
    /** @var int The nanoseconds in a millisecond. */
    private const int NANOSECONDS_PER_MILLISECOND = 1000000;

    /** @var int The milliseconds in a second. */
    private const int MILLISECONDS_PER_SECOND = 1000;

    /**
     * Constructor.
     *
     * @param  \Closure(): int  $clock
     * @param  int  $at
     */
    private function __construct(

        /** The monotonic clock, in nanoseconds. */
        private \Closure $clock,

        /** The instant on the clock the fetch must end by, in nanoseconds. */
        private int $at,
    ) {}

    /**
     * The deadline the seconds given from now on the clock.
     *
     * @param  int  $seconds
     * @param  \Closure(): int  $clock
     * @return self
     */
    public static function in(int $seconds, \Closure $clock): self
    {
        return new self($clock, $clock() + $seconds * self::MILLISECONDS_PER_SECOND * self::NANOSECONDS_PER_MILLISECOND);
    }

    /**
     * The whole milliseconds left, `0` or less once the deadline has passed.
     *
     * @return int
     */
    public function millisecondsLeft(): int
    {
        return intdiv($this->at - ($this->clock)(), self::NANOSECONDS_PER_MILLISECOND);
    }

    /**
     * Whether less than a millisecond is left.
     *
     * @return bool
     */
    public function hasPassed(): bool
    {
        return $this->millisecondsLeft() < 1;
    }

    /**
     * The Guzzle time caps of a transfer started now: what is left as its
     * `timeout`, and the connect timeout given capped to the same as its
     * `connect_timeout`, each in seconds and each at least a millisecond; or
     * `null` when less than a millisecond is left, so the transfer is not
     * started rather than started with a cap of `0`, which cURL would read as
     * none. The clock is read once, so the answer cannot pass the check and
     * then give `0`.
     *
     * @param  int  $connectTimeoutSeconds
     * @return ?array{timeout: float, connect_timeout: float}
     */
    public function transferTimeouts(int $connectTimeoutSeconds): ?array
    {
        $left = $this->millisecondsLeft();

        if ($left < 1) {
            return null;
        }

        $connect = min($connectTimeoutSeconds * self::MILLISECONDS_PER_SECOND, $left);

        return [
            'timeout'         => (float) $left    / self::MILLISECONDS_PER_SECOND,
            'connect_timeout' => (float) $connect / self::MILLISECONDS_PER_SECOND,
        ];
    }
}
