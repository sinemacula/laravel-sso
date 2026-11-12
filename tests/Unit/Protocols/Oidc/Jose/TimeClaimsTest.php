<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc\Jose;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\TimeClaims;
use Tests\Concerns\TreatsWarningsAsErrors;

/**
 * Unit tests for the package's own JWT time checks, which avoid the library's
 * off-by-one `exp` boundary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TimeClaims::class)]
final class TimeClaimsTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /** @var int The instant the claims are judged around. */
    private const int NOW = 1900000000;

    /**
     * Rows of `[claims, now, skew, max age, reason]`: each boundary at, one
     * under and one over.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: float|int, 2: int, 3: int, 4: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideBoundaries(): iterable
    {
        $valid = ['iat' => self::NOW, 'exp' => self::NOW + 300];

        yield from [
            'valid'                             => [$valid, self::NOW, 0, 300, null],
            'exp one second ahead, no skew'     => [[...$valid, 'exp' => self::NOW + 1], self::NOW, 0, 300, null],
            'exp at now, no skew'               => [[...$valid, 'exp' => self::NOW], self::NOW, 0, 300, FailureReason::ASSERTION_EXPIRED],
            'exp a microsecond ahead'           => [[...$valid, 'exp' => self::NOW + 0.000002], self::NOW, 0, 300, null],
            'exp passed, within the skew'       => [[...$valid, 'exp' => self::NOW - 59], self::NOW, 60, 300, null],
            'exp passed by the skew'            => [[...$valid, 'exp' => self::NOW - 60], self::NOW, 60, 300, FailureReason::ASSERTION_EXPIRED],
            'exp passed beyond the skew'        => [[...$valid, 'exp' => self::NOW - 61], self::NOW, 60, 300, FailureReason::ASSERTION_EXPIRED],
            'iat ahead by the skew'             => [[...$valid, 'iat' => self::NOW + 60], self::NOW, 60, 300, null],
            'iat ahead past the skew'           => [[...$valid, 'iat' => self::NOW + 61], self::NOW, 60, 300, FailureReason::ASSERTION_EXPIRED],
            'iat ahead, no skew'                => [[...$valid, 'iat' => self::NOW + 1], self::NOW, 0, 300, FailureReason::ASSERTION_EXPIRED],
            'iat at the maximum age'            => [[...$valid, 'iat' => self::NOW - 300], self::NOW, 0, 300, null],
            'iat past the maximum age'          => [[...$valid, 'iat' => self::NOW - 301], self::NOW, 0, 300, FailureReason::ASSERTION_EXPIRED],
            'iat at the maximum age and skew'   => [[...$valid, 'iat' => self::NOW - 360], self::NOW, 60, 300, null],
            'iat past the maximum age and skew' => [[...$valid, 'iat' => self::NOW - 361], self::NOW, 60, 300, FailureReason::ASSERTION_EXPIRED],
            'nbf at now plus the skew'          => [[...$valid, 'nbf' => self::NOW + 60], self::NOW, 60, 300, null],
            'nbf past now plus the skew'        => [[...$valid, 'nbf' => self::NOW + 61], self::NOW, 60, 300, FailureReason::ASSERTION_EXPIRED],
            'nbf long past'                     => [[...$valid, 'nbf' => 0], self::NOW, 0, 300, null],
            'fractional dates'                  => [['iat' => self::NOW - 0.5, 'exp' => self::NOW + 0.5], self::NOW, 0, 300, null],
            'a fractional now at exp'           => [[...$valid, 'exp' => self::NOW + 1], self::NOW + 1, 0, 300, FailureReason::ASSERTION_EXPIRED],
            'a fractional now just before exp'  => [[...$valid, 'exp' => self::NOW + 1], self::NOW + 0.999999, 0, 300, null],
            'exp missing'                       => [['iat' => self::NOW], self::NOW, 0, 300, FailureReason::ID_TOKEN_INVALID],
            'iat missing'                       => [['exp' => self::NOW + 300], self::NOW, 0, 300, FailureReason::ID_TOKEN_INVALID],
            'exp a numeric string'              => [[...$valid, 'exp' => (string) (self::NOW + 300)], self::NOW, 0, 300, FailureReason::ID_TOKEN_INVALID],
            'exp too large, kept as digits'     => [[...$valid, 'exp' => '99999999999999999999'], self::NOW, 0, 300, FailureReason::ID_TOKEN_INVALID],
            'exp null'                          => [[...$valid, 'exp' => null], self::NOW, 0, 300, FailureReason::ID_TOKEN_INVALID],
            'iat a boolean'                     => [[...$valid, 'iat' => true], self::NOW, 0, 300, FailureReason::ID_TOKEN_INVALID],
            'nbf a string'                      => [[...$valid, 'nbf' => '0'], self::NOW, 0, 300, FailureReason::ID_TOKEN_INVALID],
            'nbf null'                          => [[...$valid, 'nbf' => null], self::NOW, 0, 300, FailureReason::ID_TOKEN_INVALID],
            'iat a list'                        => [[...$valid, 'iat' => [self::NOW]], self::NOW, 0, 300, FailureReason::ID_TOKEN_INVALID],
        ];
    }

    /**
     * Each time claim is judged at its boundary as the package states it.
     *
     * @param  array<string, mixed>  $claims
     * @param  float|int  $now
     * @param  int  $skew
     * @param  int  $maxAge
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideBoundaries')]
    public function testEachTimeClaimIsJudgedAtItsBoundary(array $claims, float|int $now, int $skew, int $maxAge, ?FailureReason $reason): void
    {
        self::assertSame($reason, TimeClaims::check($claims, self::at($now), $skew, $maxAge));
    }

    /**
     * Four checks in a row in one process, each with its own clock and skew,
     * each see only their own: accepted, accepted, refused, accepted.
     *
     * @return void
     */
    public function testChecksInARowEachSeeTheirOwnClockAndSkew(): void
    {
        $claims = ['iat' => self::NOW - 300, 'exp' => self::NOW];

        self::assertSame(
            [null, null, FailureReason::ASSERTION_EXPIRED, null],
            [
                TimeClaims::check($claims, self::at(self::NOW - 10), 0, 600),
                TimeClaims::check($claims, self::at(self::NOW + 30), 60, 600),
                TimeClaims::check($claims, self::at(self::NOW + 30), 0, 600),
                TimeClaims::check($claims, self::at(self::NOW - 10), 0, 600),
            ],
        );
    }

    /**
     * Two checks interleaved in fibres in one process each keep their own clock
     * and skew.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInterleavedChecksKeepTheirOwnClockAndSkew(): void
    {
        $claims  = ['iat' => self::NOW - 300, 'exp' => self::NOW];
        $results = [];

        $first = new \Fiber(static function () use ($claims, &$results): void {
            $now = self::at(self::NOW + 30);

            \Fiber::suspend();

            $results['first'] = TimeClaims::check($claims, $now, 60, 600);
        });

        $first->start();

        $results['second'] = TimeClaims::check($claims, self::at(self::NOW + 30), 0, 600);

        $first->resume();

        self::assertSame(['second' => FailureReason::ASSERTION_EXPIRED, 'first' => null], $results);
    }

    /**
     * A NumericDate is a JSON number, kept at full precision.
     *
     * @return void
     */
    public function testANumericDateIsAJsonNumber(): void
    {
        self::assertSame([1.0, 1.5, -1.0, null, null, null], array_map(TimeClaims::numericDate(...), [1, 1.5, -1, '1', true, null]));
        self::assertSame(1900000000.25, TimeClaims::instant(self::at(1900000000.25)));
    }

    /**
     * The instant of the seconds since the epoch, to the microsecond.
     *
     * @param  float|int  $seconds
     * @return \Carbon\CarbonImmutable
     *
     * @throws \LogicException
     */
    private static function at(float|int $seconds): CarbonImmutable
    {
        return CarbonImmutable::createFromFormat('U.u', sprintf('%.6F', $seconds), 'UTC') ?: throw new \LogicException('Not an instant.');
    }
}
