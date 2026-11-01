<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\Clock;

/**
 * A clock for tests that holds one instant until the test moves it, so a test
 * of skew, expiry or a maximum age neither waits nor depends on the time it
 * runs at (SSO-11.13).
 *
 * Bind it in place of the package's clock with
 * `$app->instance(Clock::class, new FrozenClock('2026-10-31T12:00:00Z'))`, then
 * move it with `advance()` or `setTo()`. It reads nothing from Laravel's test
 * clock once built, so freezing or travelling Laravel's clock does not move it;
 * the package's default clock follows Laravel's instead. An instant given as a
 * string is parsed as `CarbonImmutable::parse()` parses it, and one Carbon
 * cannot parse throws an `InvalidArgumentException`.
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
     * Move the clock by the seconds given, backwards when negative.
     *
     * @param  int  $seconds
     * @return void
     */
    public function advance(int $seconds): void
    {
        $this->now = $this->now->addSeconds($seconds);
    }

    /**
     * Move the clock to the instant given.
     *
     * @param  \DateTimeInterface|string  $instant
     * @return void
     */
    public function setTo(\DateTimeInterface|string $instant): void
    {
        $this->now = self::instant($instant);
    }

    /**
     * The instant given, as a `CarbonImmutable`.
     *
     * @param  \DateTimeInterface|string  $instant
     * @return \Carbon\CarbonImmutable
     */
    private static function instant(\DateTimeInterface|string $instant): CarbonImmutable
    {
        return $instant instanceof \DateTimeInterface ? CarbonImmutable::instance($instant) : CarbonImmutable::parse($instant);
    }
}
