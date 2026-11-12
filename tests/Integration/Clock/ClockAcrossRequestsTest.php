<?php

declare(strict_types = 1);

namespace Tests\Integration\Clock;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Clock\SystemClock;
use SineMacula\Laravel\Sso\Contracts\Clock;
use Tests\TestCase;

/**
 * Integration tests of one shared clock across a worker's requests and jobs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SystemClock::class)]
final class ClockAcrossRequestsTest extends TestCase
{
    /** @var string The first instant the tests freeze Laravel's clock at. */
    private const string FIRST = '2026-10-31T12:00:00.250000Z';

    /** @var string The second instant the tests freeze Laravel's clock at. */
    private const string SECOND = '2026-10-31T12:05:00.750000Z';

    /**
     * Restore Laravel's test clock, so no test leaks into the next.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * One resolved clock follows Laravel's test clock and survives scoped
     * flushes.
     *
     * @return void
     */
    public function testOneClockFollowsLaravelsClockBetweenUses(): void
    {
        $clock = $this->clock();

        $this->travelTo(CarbonImmutable::parse(self::FIRST));

        self::assertSame(self::micro(self::FIRST), $clock->now()->format('U.u'));

        $this->app?->forgetScopedInstances();

        Carbon::setTestNow(CarbonImmutable::parse(self::SECOND));

        self::assertSame($clock, $this->clock());
        self::assertSame(self::micro(self::SECOND), $clock->now()->format('U.u'));

        Carbon::setTestNow();

        $before = CarbonImmutable::now();
        $now    = $clock->now();
        $after  = CarbonImmutable::now();

        self::assertTrue($now->betweenIncluded($before, $after));
    }

    /**
     * Two requests share the clock and each reads its own instant.
     *
     * @return void
     */
    public function testEachRequestReadsItsOwnInstantFromTheSameClock(): void
    {
        Route::get('/clock', static fn (Clock $clock): JsonResponse => new JsonResponse([
            'clock' => spl_object_id($clock),
            'now'   => $clock->now()->format('U.u'),
        ]));

        $this->travelTo(CarbonImmutable::parse(self::FIRST));

        $first = $this->getJson('/clock')->assertOk()->json();

        $this->travelTo(CarbonImmutable::parse(self::SECOND));

        $second = $this->getJson('/clock')->assertOk()->json();

        self::assertIsArray($first);
        self::assertIsArray($second);
        self::assertSame(self::micro(self::FIRST), $first['now']);
        self::assertSame(self::micro(self::SECOND), $second['now']);
        self::assertSame($first['clock'], $second['clock']);
        self::assertSame(spl_object_id($this->clock()), $second['clock']);
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

    /**
     * The instant, as seconds and microseconds since the epoch.
     *
     * @param  string  $instant
     * @return string
     */
    private static function micro(string $instant): string
    {
        return CarbonImmutable::parse($instant)->format('U.u');
    }
}
