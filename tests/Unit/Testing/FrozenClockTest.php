<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Testing\FrozenClock;

/**
 * Unit tests for the frozen clock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FrozenClock::class)]
final class FrozenClockTest extends TestCase
{
    /** @var string The instant the tests freeze the clock at. */
    private const string INSTANT = '2026-10-31T12:00:00.500000Z';

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
     * The clock answers the instant it was given, to the microsecond, on every
     * call, and Laravel's test clock does not move it.
     *
     * @return void
     */
    public function testHoldsItsInstant(): void
    {
        $clock = new FrozenClock(self::INSTANT);

        self::assertSame(self::micro(self::INSTANT), $clock->now()->format('U.u'));

        Carbon::setTestNow(CarbonImmutable::parse('2030-01-01T00:00:00Z'));

        self::assertSame(self::micro(self::INSTANT), $clock->now()->format('U.u'));
        self::assertSame($clock->now(), $clock->now());
    }

    /**
     * `advance()` moves the clock forwards by the seconds given, backwards when
     * they are negative, and not at all by none.
     *
     * @return void
     */
    public function testAdvancesForwardsAndBackwards(): void
    {
        $clock = new FrozenClock(self::INSTANT);

        $clock->advance(90);

        self::assertSame(self::micro('2026-10-31T12:01:30.500000Z'), $clock->now()->format('U.u'));

        $clock->advance(-150);

        self::assertSame(self::micro('2026-10-31T11:59:00.500000Z'), $clock->now()->format('U.u'));

        $clock->advance(0);

        self::assertSame(self::micro('2026-10-31T11:59:00.500000Z'), $clock->now()->format('U.u'));
    }

    /**
     * An instant answered before the clock moved is not changed by the move.
     *
     * @return void
     */
    public function testAnInstantAnsweredEarlierIsNotChanged(): void
    {
        $clock  = new FrozenClock(self::INSTANT);
        $before = $clock->now();

        $clock->advance(60);
        $clock->setTo('2027-01-01T00:00:00Z');

        self::assertSame(self::micro(self::INSTANT), $before->format('U.u'));
    }

    /**
     * Rows of `[an instant, as a string or a date]`: each form of
     * 2026-10-31T12:00:00.5Z the clock accepts.
     *
     * @return iterable<string, array{0: \DateTimeInterface|string}>
     */
    public static function provideInstants(): iterable
    {
        yield from [
            'an ISO 8601 string'     => [self::INSTANT],
            'a string in a zone'     => ['2026-10-31T13:00:00.500000+01:00'],
            'a DateTime'             => [new \DateTime(self::INSTANT)],
            'a DateTimeImmutable'    => [new \DateTimeImmutable(self::INSTANT)],
            'a Carbon'               => [Carbon::parse(self::INSTANT)],
            'a CarbonImmutable'      => [CarbonImmutable::parse(self::INSTANT)],
            'a date in another zone' => [new \DateTimeImmutable('2026-10-31 08:00:00.500000', new \DateTimeZone('America/New_York'))],
        ];
    }

    /**
     * The constructor takes the instant as a string or any date, and holds it
     * as a `CarbonImmutable`.
     *
     * @param  \DateTimeInterface|string  $instant
     * @return void
     */
    #[DataProvider('provideInstants')]
    public function testIsBuiltAtAStringOrADate(\DateTimeInterface|string $instant): void
    {
        $now = (new FrozenClock($instant))->now();

        self::assertSame(CarbonImmutable::class, $now::class);
        self::assertSame(self::micro(self::INSTANT), $now->format('U.u'));
    }

    /**
     * `setTo()` takes the instant as a string or any date, and moves the clock
     * there, backwards as well as forwards.
     *
     * @param  \DateTimeInterface|string  $instant
     * @return void
     */
    #[DataProvider('provideInstants')]
    public function testIsSetToAStringOrADate(\DateTimeInterface|string $instant): void
    {
        $clock = new FrozenClock('2030-01-01T00:00:00Z');

        $clock->setTo($instant);

        self::assertSame(CarbonImmutable::class, $clock->now()::class);
        self::assertSame(self::micro(self::INSTANT), $clock->now()->format('U.u'));
    }

    /**
     * A mutable date given to the clock can change without moving the clock.
     *
     * @return void
     */
    public function testKeepsItsOwnCopyOfAMutableDate(): void
    {
        $date  = new \DateTime(self::INSTANT);
        $clock = new FrozenClock($date);

        $date->modify('+1 day');

        self::assertSame(self::micro(self::INSTANT), $clock->now()->format('U.u'));

        $clock->setTo($date);
        $date->modify('+1 day');

        self::assertSame(self::micro('2026-11-01T12:00:00.500000Z'), $clock->now()->format('U.u'));
    }

    /**
     * Built with no instant, the clock holds the instant it was built at, and
     * stays there while time moves on.
     *
     * @return void
     */
    public function testDefaultsToTheInstantOfConstruction(): void
    {
        Carbon::setTestNow(CarbonImmutable::parse(self::INSTANT));

        $clock = new FrozenClock;

        Carbon::setTestNow(CarbonImmutable::parse(self::INSTANT)->addHour());

        self::assertSame(self::micro(self::INSTANT), $clock->now()->format('U.u'));
    }

    /**
     * Built with no instant while nothing is frozen, the clock holds the real
     * instant it was built at.
     *
     * @return void
     */
    public function testDefaultsToTheRealInstantWhenNothingIsFrozen(): void
    {
        $before = CarbonImmutable::now();
        $clock  = new FrozenClock;
        $after  = CarbonImmutable::now();

        self::assertTrue($clock->now()->betweenIncluded($before, $after));
    }

    /**
     * A string that names no instant throws `InvalidArgumentException` instead
     * of freezing at another time.
     *
     * @return void
     */
    public function testRefusesAStringThatNamesNoInstant(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new FrozenClock('not an instant');
    }

    /**
     * The instant, as seconds and microseconds since the epoch, so instants in
     * different zones compare as the same moment.
     *
     * @param  string  $instant
     * @return string
     */
    private static function micro(string $instant): string
    {
        return CarbonImmutable::parse($instant)->format('U.u');
    }
}
