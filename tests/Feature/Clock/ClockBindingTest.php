<?php

declare(strict_types = 1);

namespace Tests\Feature\Clock;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Clock\SystemClock;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use SineMacula\Laravel\Sso\Testing\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for the clock's binding in a booted application: the system
 * clock by default, shared as a singleton, a clock the application bound before
 * the package registers kept, and one bound afterwards used instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoServiceProvider::class)]
#[CoversClass(SystemClock::class)]
#[CoversClass(FrozenClock::class)]
final class ClockBindingTest extends TestCase
{
    /**
     * With nothing else bound, the container answers the system clock.
     *
     * @return void
     */
    public function testTheSystemClockIsTheDefault(): void
    {
        self::assertInstanceOf(SystemClock::class, $this->clock());
    }

    /**
     * The clock holds nothing, so one instance is shared by every caller.
     *
     * @return void
     */
    public function testTheClockIsASingleton(): void
    {
        self::assertSame($this->clock(), $this->clock());
    }

    /**
     * A clock the application bound before the package's provider registers is
     * kept, never replaced by the default.
     *
     * Testbench registers the provider before a test can bind anything, so the
     * test binds its clock and then runs the provider's registration again, as
     * a fresh application would.
     *
     * @return void
     */
    public function testAClockBoundBeforeTheProviderRegistersIsKept(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app   = $this->app;
        $clock = new FrozenClock('2026-10-31T12:00:00Z');

        $app->instance(Clock::class, $clock);

        (new SsoServiceProvider($app))->register();

        self::assertSame($clock, $this->clock());
        self::assertSame('2026-10-31T12:00:00+00:00', $this->clock()->now()->toIso8601String());
    }

    /**
     * A frozen clock bound once the package has registered, and after the
     * default was resolved, replaces the default for every later caller.
     *
     * @return void
     */
    public function testAFrozenClockBoundAfterwardsReplacesTheDefault(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        self::assertInstanceOf(SystemClock::class, $this->clock());

        $clock = new FrozenClock('2026-10-31T12:00:00Z');

        $app->instance(Clock::class, $clock);

        self::assertSame($clock, $this->clock());

        $clock->advance(30);

        self::assertSame('2026-10-31T12:00:30+00:00', $this->clock()->now()->toIso8601String());
    }

    /**
     * The clock the container answers.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\Clock
     */
    private function clock(): Clock
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(Clock::class);
    }
}
