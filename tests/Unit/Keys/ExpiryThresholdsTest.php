<?php

declare(strict_types = 1);

namespace Tests\Unit\Keys;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Keys\ExpiryThresholds;

/**
 * Unit tests for the thresholds' validation and which one a key has reached
 * (SSO-2.6, SSO-11.12).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExpiryThresholds::class)]
final class ExpiryThresholdsTest extends TestCase
{
    /**
     * Rows of `[value]`: what the setting may not be.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideRefusedValues(): iterable
    {
        yield 'nothing' => [null];
        yield 'a word' => ['soon'];
        yield 'an integer' => [30];
        yield 'empty' => [[]];
        yield 'no zero' => [[30, 7]];
        yield 'a duplicate' => [[7, 7, 0]];
        yield 'a duplicate in another form' => [[7, '7', 0]];
        yield 'over a year' => [[366, 0]];
        yield 'negative' => [[-1, 0]];
        yield 'a fraction' => [[1.5, 0]];
        yield 'a boolean' => [[true, 0]];
        yield 'a padded string' => [['07', 0]];
        yield 'a keyed array' => [['soon' => 7, 'now' => 0]];
        yield 'a nested list' => [[[7], 0]];
    }

    /**
     * Anything but a list of distinct integers from 0 to 365 with 0 among them
     * fails closed, naming the key.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideRefusedValues')]
    public function testRefusesAMalformedValue(mixed $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('sso.keys.expiry_thresholds must be a list of distinct integers from 0 to 365, including 0.');

        ExpiryThresholds::parse($value);
    }

    /**
     * The edges of the range and any order are accepted, strings as `env()`
     * gives them too, and the largest is found whatever the order.
     *
     * @return void
     */
    public function testAcceptsAnyOrderAndTheEdgesOfTheRange(): void
    {
        self::assertSame(365, ExpiryThresholds::parse([0, 365, 1])->largest());
        self::assertSame(30, ExpiryThresholds::parse(['7', '30', '0'])->largest());
        self::assertSame(0, ExpiryThresholds::parse([0])->largest());
    }

    /**
     * Rows of `[seconds left, the threshold reached]`.
     *
     * @return iterable<string, array{0: int, 1: ?int}>
     */
    public static function provideReached(): iterable
    {
        yield 'beyond the largest' => [864001, null];
        yield 'at the largest' => [864000, 10];
        yield 'a second short of the next' => [86401, 10];
        yield 'at the next' => [86400, 1];
        yield 'a second left' => [1, 1];
        yield 'at the end' => [0, 0];
        yield 'past the end' => [-1, 0];
    }

    /**
     * The most urgent threshold reached, whatever order the list was given in.
     *
     * @param  int  $left
     * @param  ?int  $reached
     * @return void
     */
    #[DataProvider('provideReached')]
    public function testAnswersTheMostUrgentThresholdReached(int $left, ?int $reached): void
    {
        $now = CarbonImmutable::parse('2026-11-01T12:00:00Z');

        self::assertSame($reached, ExpiryThresholds::parse([1, 10, 0])->reachedBy($now->addSeconds($left), $now));
        self::assertSame($reached, ExpiryThresholds::parse([10, 0, 1])->reachedBy($now->addSeconds($left), $now));
    }
}
