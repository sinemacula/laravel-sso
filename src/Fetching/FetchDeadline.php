<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching;

/**
 * The single deadline shared by every lookup and hop of one fetch, on a
 * monotonic clock so wall-clock changes and test clocks cannot move it.
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
     * Create the deadline the given seconds from now.
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
     * The whole milliseconds left, `0` or less once passed.
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
     * The Guzzle time caps of a transfer started now, or `null` when under a
     * millisecond is left, since cURL reads a timeout of `0` as none.
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
