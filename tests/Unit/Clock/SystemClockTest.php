<?php

declare(strict_types = 1);

namespace Tests\Unit\Clock;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Support\Carbon as LaravelCarbon;
use Illuminate\Support\Facades\Date;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Clock\SystemClock;

/**
 * Unit tests for the default clock: always a `CarbonImmutable`, the instant
 * Laravel's test clock is set to, whatever class the date factory makes, and
 * read afresh on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SystemClock::class)]
final class SystemClockTest extends TestCase
{
    /** @var string The instant the tests freeze Laravel's clock at. */
    private const string INSTANT = '2026-10-31T12:00:00.123456Z';

    /**
     * Restore Laravel's date factory and test clock, so no test leaks into the
     * next.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Date::useDefault();
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * The instant is a `CarbonImmutable` itself, never a subclass or a mutable
     * date, so a caller can add to it without changing what another holds.
     *
     * @return void
     */
    public function testAnswersACarbonImmutable(): void
    {
        $now = (new SystemClock)->now();

        self::assertSame(CarbonImmutable::class, $now::class);
    }

    /**
     * Freezing Laravel's clock with `Carbon::setTestNow()` freezes the
     * package's, to the microsecond, and moving it moves the package's.
     *
     * @return void
     */
    public function testFollowsCarbonsTestClock(): void
    {
        $clock = new SystemClock;

        Carbon::setTestNow(CarbonImmutable::parse(self::INSTANT));

        self::assertSame(CarbonImmutable::parse(self::INSTANT)->format('U.u'), $clock->now()->format('U.u'));

        Carbon::setTestNow(CarbonImmutable::parse(self::INSTANT)->addSeconds(90));

        self::assertSame(CarbonImmutable::parse('2026-10-31T12:01:30.123456Z')->format('U.u'), $clock->now()->format('U.u'));
    }

    /**
     * Freezing Laravel's clock through the `Date` facade freezes the package's.
     *
     * @return void
     */
    public function testFollowsTheDateFacadesTestClock(): void
    {
        Date::setTestNow(CarbonImmutable::parse(self::INSTANT));

        self::assertSame(CarbonImmutable::parse(self::INSTANT)->format('U.u'), (new SystemClock)->now()->format('U.u'));
    }

    /**
     * Rows of `[the class the date factory makes, or null for its default]`.
     *
     * @return iterable<string, array{0: ?class-string<\DateTimeInterface>}>
     */
    public static function provideDateClasses(): iterable
    {
        yield from [
            'the default factory'      => [null],
            'Laravel\'s Carbon'        => [LaravelCarbon::class],
            'Carbon'                   => [Carbon::class],
            'CarbonImmutable'          => [CarbonImmutable::class],
            'PHP\'s DateTimeImmutable' => [\DateTimeImmutable::class],
            'PHP\'s mutable DateTime'  => [\DateTime::class],
        ];
    }

    /**
     * Whatever class the application's date factory makes, the clock answers
     * the frozen instant as a `CarbonImmutable`.
     *
     * @param  ?class-string<\DateTimeInterface>  $class
     * @return void
     */
    #[DataProvider('provideDateClasses')]
    public function testFollowsTheDateFactory(?string $class): void
    {
        if ($class === null) {
            Date::useDefault();
        } else {
            Date::use($class);
        }

        Carbon::setTestNow(CarbonImmutable::parse(self::INSTANT));

        $now = (new SystemClock)->now();

        self::assertSame(CarbonImmutable::class, $now::class);
        self::assertSame(CarbonImmutable::parse(self::INSTANT)->format('U.u'), $now->format('U.u'));
    }

    /**
     * A date factory that builds each date through a callable is followed too.
     *
     * @return void
     */
    public function testFollowsACallableDateFactory(): void
    {
        Date::useCallable(static fn (Carbon $date): \DateTime => new \DateTime($date->format('Y-m-d H:i:s.u'), $date->getTimezone()));

        Carbon::setTestNow(CarbonImmutable::parse(self::INSTANT));

        $now = (new SystemClock)->now();

        self::assertSame(CarbonImmutable::class, $now::class);
        self::assertSame(CarbonImmutable::parse(self::INSTANT)->format('U.u'), $now->format('U.u'));
    }

    /**
     * With Laravel's clock running, the clock answers the real current instant.
     *
     * @return void
     */
    public function testAnswersTheCurrentInstantWhenNothingIsFrozen(): void
    {
        $before = CarbonImmutable::now();
        $now    = (new SystemClock)->now();
        $after  = CarbonImmutable::now();

        self::assertTrue($now->betweenIncluded($before, $after));
    }

    /**
     * Each call reads the time again, and an instant answered earlier is not
     * changed by a later one.
     *
     * @return void
     */
    public function testReadsTheTimeOnEveryCall(): void
    {
        $clock = new SystemClock;

        Carbon::setTestNow(CarbonImmutable::parse(self::INSTANT));

        $first = $clock->now();

        Carbon::setTestNow(CarbonImmutable::parse(self::INSTANT)->addHour());

        $second = $clock->now();

        self::assertSame(CarbonImmutable::parse(self::INSTANT)->format('U.u'), $first->format('U.u'));
        self::assertSame(CarbonImmutable::parse('2026-10-31T13:00:00.123456Z')->format('U.u'), $second->format('U.u'));
    }
}
