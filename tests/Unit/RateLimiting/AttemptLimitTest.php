<?php

declare(strict_types = 1);

namespace Tests\Unit\RateLimiting;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\RateLimiting\AttemptLimit;

/**
 * Unit tests for an attempt limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptLimit::class)]
final class AttemptLimitTest extends TestCase
{
    /**
     * Rows of `[max, decay seconds, accepted]` at and beyond each bound.
     *
     * @return iterable<string, array{0: int, 1: int, 2: bool}>
     */
    public static function provideBounds(): iterable
    {
        yield from [
            'no attempts'         => [0, 60, false],
            'negative attempts'   => [-1, 60, false],
            'one attempt'         => [1, 60, true],
            'a million attempts'  => [1000000, 60, true],
            'more than a million' => [1000001, 60, false],
            'no window'           => [5, 0, false],
            'a negative window'   => [5, -60, false],
            'one-second window'   => [5, 1, true],
            'one-day window'      => [5, 86400, true],
            'longer than a day'   => [5, 86401, false],
        ];
    }

    /**
     * A limit allows 1 to 1000000 attempts in a window of 1 to 86400 seconds.
     *
     * @param  int  $max
     * @param  int  $decay
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideBounds')]
    public function testAcceptsExactlyItsBounds(int $max, int $decay, bool $accepted): void
    {
        if (!$accepted) {
            $this->expectException(\InvalidArgumentException::class);
            $this->expectExceptionMessage("A limit needs 1 to 1000000 attempts in a window of 1 to 86400 seconds, {$max} in {$decay} given.");
        }

        $limit = new AttemptLimit($max, $decay);

        self::assertSame([$max, $decay], [$limit->max, $limit->decaySeconds]);
    }

    /**
     * Rows of `[decay seconds, now, window end]`.
     *
     * @return iterable<string, array{0: int, 1: int, 2: int}>
     */
    public static function provideWindows(): iterable
    {
        yield from [
            'start of a window'       => [60, 1800000000, 1800000060],
            'inside a window'         => [60, 1800000015, 1800000060],
            'last second of a window' => [60, 1800000059, 1800000060],
            'one-second windows'      => [1, 1800000123, 1800000124],
            'hour-long windows'       => [3600, 1800000123, 1800003600],
            'day-long windows'        => [86400, 1800000123, 1800057600],
        ];
    }

    /**
     * A window ends at the next multiple of its length after now.
     *
     * @param  int  $decay
     * @param  int  $now
     * @param  int  $end
     * @return void
     */
    #[DataProvider('provideWindows')]
    public function testWindowsAreAlignedToTheClock(int $decay, int $now, int $end): void
    {
        self::assertSame($end, (new AttemptLimit(5, $decay))->windowEnd($now));
    }
}
