<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\Clock;

/**
 * A test clock that holds one instant until moved. Laravel's test clock does
 * not move it, unlike the package's default clock.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FrozenClock implements Clock
{
    /** @var \Carbon\CarbonImmutable The instant the clock holds. */
    private CarbonImmutable $now;

    /**
     * Constructor.
     *
     * @param  \DateTimeInterface|string|null  $now
     */
    public function __construct(\DateTimeInterface|string|null $now = null)
    {
        $this->now = $now === null ? CarbonImmutable::now() : self::instant($now);
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
     * Move the clock by the seconds, backwards when negative.
     *
     * @param  int  $seconds
     * @return void
     */
    public function advance(int $seconds): void
    {
        $this->now = $this->now->addSeconds($seconds);
    }

    /**
     * Move the clock to the instant.
     *
     * @param  \DateTimeInterface|string  $instant
     * @return void
     */
    public function setTo(\DateTimeInterface|string $instant): void
    {
        $this->now = self::instant($instant);
    }

    /**
     * Convert the instant to a `CarbonImmutable`.
     *
     * @param  \DateTimeInterface|string  $instant
     * @return \Carbon\CarbonImmutable
     */
    private static function instant(\DateTimeInterface|string $instant): CarbonImmutable
    {
        return $instant instanceof \DateTimeInterface ? CarbonImmutable::instance($instant) : CarbonImmutable::parse($instant);
    }
}
