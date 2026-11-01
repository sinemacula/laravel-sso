<?php

declare(strict_types = 1);

namespace Tests\Unit\Fetching;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Fetching\FetchDeadline;

/**
 * Unit tests for a fetch's one deadline: the timeout from the moment it is set,
 * counted in whole milliseconds on the monotonic clock given, passed once less
 * than a millisecond is left, and the time caps of a transfer started at any
 * point before it, or none once less than a millisecond is left.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FetchDeadline::class)]
final class FetchDeadlineTest extends TestCase
{
    /** @var int The nanoseconds in a millisecond. */
    private const int MILLISECOND = 1000000;

    /** @var int The nanoseconds in a second. */
    private const int SECOND = 1000000000;

    /** @var int The test's monotonic clock, in nanoseconds. */
    private int $now = 0;

    /**
     * The deadline is the seconds given from the instant it is set, not from
     * the clock's zero.
     *
     * @return void
     */
    public function testIsTheTimeoutFromWhenItIsSet(): void
    {
        $this->now = 123 * self::SECOND;
        $deadline  = $this->deadline(10);

        self::assertSame(10000, $deadline->millisecondsLeft());

        $this->now += 4 * self::SECOND;

        self::assertSame(6000, $deadline->millisecondsLeft());
        self::assertFalse($deadline->hasPassed());
    }

    /**
     * Rows of `[nanoseconds elapsed of a one-second deadline, milliseconds
     * left, passed]`.
     *
     * @return iterable<string, array{int, int, bool}>
     */
    public static function provideElapsedTimes(): iterable
    {
        yield from [
            'a millisecond left'            => [999 * self::MILLISECOND, 1, false],
            'a millisecond and a part left' => [998 * self::MILLISECOND + 1, 1, false],
            'a part of a millisecond left'  => [999 * self::MILLISECOND + 1, 0, true],
            'none left'                     => [self::SECOND, 0, true],
            'well past'                     => [3 * self::SECOND, -2000, true],
        ];
    }

    /**
     * Time left is counted in whole milliseconds, and the deadline has passed
     * once less than one is left: cURL reads a timeout of `0` as none.
     *
     * @param  int  $elapsed
     * @param  int  $millisecondsLeft
     * @param  bool  $passed
     * @return void
     */
    #[DataProvider('provideElapsedTimes')]
    public function testCountsWholeMillisecondsLeft(int $elapsed, int $millisecondsLeft, bool $passed): void
    {
        $deadline = $this->deadline(1);

        $this->now += $elapsed;

        self::assertSame($millisecondsLeft, $deadline->millisecondsLeft());
        self::assertSame($passed, $deadline->hasPassed());
    }

    /**
     * Rows of `[nanoseconds elapsed of a ten-second deadline, timeout, connect
     * timeout]`, under a five-second connect timeout.
     *
     * @return iterable<string, array{int, float, float}>
     */
    public static function provideTransferTimes(): iterable
    {
        yield from [
            'at once'                               => [0, 10.0, 5.0],
            'leaving more than the connect timeout' => [4250 * self::MILLISECOND, 5.75, 5.0],
            'leaving exactly the connect timeout'   => [5 * self::SECOND, 5.0, 5.0],
            'leaving less than the connect timeout' => [7 * self::SECOND, 3.0, 3.0],
            'leaving a millisecond'                 => [10 * self::SECOND - self::MILLISECOND, 0.001, 0.001],
            'leaving a millisecond and a part'      => [10 * self::SECOND - self::MILLISECOND - 1, 0.001, 0.001],
        ];
    }

    /**
     * A transfer is given what is left as its timeout, and the connect timeout
     * capped to the same, in seconds.
     *
     * @param  int  $elapsed
     * @param  float  $timeout
     * @param  float  $connectTimeout
     * @return void
     */
    #[DataProvider('provideTransferTimes')]
    public function testGivesATransferOnlyTheTimeLeft(int $elapsed, float $timeout, float $connectTimeout): void
    {
        $deadline = $this->deadline(10);

        $this->now += $elapsed;

        self::assertSame(['timeout' => $timeout, 'connect_timeout' => $connectTimeout], $deadline->transferTimeouts(5));
    }

    /**
     * Rows of `[nanoseconds elapsed of a ten-second deadline]` that leave less
     * than a millisecond.
     *
     * @return iterable<string, array{int}>
     */
    public static function provideSpentTimes(): iterable
    {
        yield from [
            'a part of a millisecond left' => [10 * self::SECOND - self::MILLISECOND + 1],
            'a nanosecond left'            => [10 * self::SECOND - 1],
            'none left'                    => [10 * self::SECOND],
            'past the deadline'            => [11 * self::SECOND],
        ];
    }

    /**
     * With less than a millisecond left, a transfer is given no caps at all
     * rather than caps of `0`, which cURL reads as none, so it is not started.
     *
     * @param  int  $elapsed
     * @return void
     */
    #[DataProvider('provideSpentTimes')]
    public function testGivesNoTransferCapsOnceLessThanAMillisecondIsLeft(int $elapsed): void
    {
        $deadline = $this->deadline(10);

        $this->now += $elapsed;

        self::assertNull($deadline->transferTimeouts(5));
    }

    /**
     * The time caps are read from the clock once: a clock that moves on with
     * every read cannot pass a check and then give a cap of `0`.
     *
     * @return void
     */
    public function testReadsTheClockOnceForTheTransferCaps(): void
    {
        $instants = [0, self::SECOND - 3 * self::MILLISECOND / 2, self::SECOND - self::MILLISECOND / 2];
        $deadline = FetchDeadline::in(1, static function () use (&$instants): int {
            return (int) array_shift($instants);
        });

        self::assertSame(['timeout' => 0.001, 'connect_timeout' => 0.001], $deadline->transferTimeouts(5));
        self::assertSame([self::SECOND - self::MILLISECOND / 2], $instants);
        self::assertNull($deadline->transferTimeouts(5));
    }

    /**
     * A deadline the seconds given from now on the test's clock.
     *
     * @param  int  $seconds
     * @return \SineMacula\Laravel\Sso\Fetching\FetchDeadline
     */
    private function deadline(int $seconds): FetchDeadline
    {
        return FetchDeadline::in($seconds, fn (): int => $this->now);
    }
}
