<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc\IdTokens;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokens\AuthenticationTimeRules;
use Tests\Concerns\TreatsWarningsAsErrors;

/**
 * Unit tests for an ID token's `auth_time` rules.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationTimeRules::class)]
final class AuthenticationTimeRulesTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /** @var int The instant the claims are judged at. */
    private const int NOW = 1900000000;

    /** @var int The skew most rows are judged with. */
    private const int SKEW = 60;

    /**
     * Rows of `[claims, max age, reason]`: `auth_time` absent.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: ?int, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideAbsentTimes(): iterable
    {
        $invalid = FailureReason::ID_TOKEN_INVALID;

        yield from [
            'absent, no max_age'            => [[], null, null],
            'absent, iat there, no max_age' => [['iat' => self::NOW], null, null],
            'absent, max_age 300'           => [[], 300, $invalid],
            'absent, max_age 0'             => [[], 0, $invalid],
            'absent, iat recent, max_age'   => [['iat' => self::NOW], 300, $invalid],
            'absent, iat recent, max_age 0' => [['iat' => self::NOW], 0, $invalid],
            'not a number, max_age'         => [['auth_time' => (string) self::NOW], 300, $invalid],
            'not a number, no max_age'      => [['auth_time' => (string) self::NOW], null, null],
        ];
    }

    /**
     * Without `auth_time`, the token passes unless `max_age` was asked for; it
     * is never inferred from `iat`.
     *
     * @param  array<string, mixed>  $claims
     * @param  ?int  $maxAge
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideAbsentTimes')]
    public function testAnAbsentTimeIsRequiredOnlyWithMaxAge(array $claims, ?int $maxAge, ?FailureReason $reason): void
    {
        self::assertSame($reason, AuthenticationTimeRules::refusal($claims, self::at(self::NOW), self::SKEW, $maxAge));
    }

    /**
     * Rows of `[auth_time, skew, reason]`: around now plus the skew.
     *
     * @return iterable<string, array{0: float|int, 1: int, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideFutureTimes(): iterable
    {
        $expired = FailureReason::ASSERTION_EXPIRED;

        yield from [
            'now'                    => [self::NOW, 60, null],
            'under now and skew'     => [self::NOW + 59, 60, null],
            'at now and skew'        => [self::NOW + 60, 60, null],
            'over now and skew'      => [self::NOW + 61, 60, $expired],
            'just over now and skew' => [self::NOW + 60.00001, 60, $expired],
            'just under, no skew'    => [self::NOW - 0.00001, 0, null],
            'at now, no skew'        => [self::NOW, 0, null],
            'just over, no skew'     => [self::NOW + 0.00001, 0, $expired],
            'a second over, no skew' => [self::NOW + 1, 0, $expired],
        ];
    }

    /**
     * An `auth_time` past now and the skew is `assertion_expired`.
     *
     * @param  float|int  $time
     * @param  int  $skew
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideFutureTimes')]
    public function testAFutureTimeBeyondTheSkewIsExpired(float|int $time, int $skew, ?FailureReason $reason): void
    {
        self::assertSame($reason, AuthenticationTimeRules::refusal(['auth_time' => $time], self::at(self::NOW), $skew, null));
    }

    /**
     * Rows of `[auth_time, max age, skew, reason]`: around now less the maximum
     * age and the skew.
     *
     * @return iterable<string, array{0: float|int, 1: int, 2: int, 3: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideOldTimes(): iterable
    {
        $expired = FailureReason::AUTHENTICATION_EXPIRED;

        yield from [
            'under max_age and skew'          => [self::NOW - 359, 300, 60, null],
            'at max_age and skew'             => [self::NOW - 360, 300, 60, null],
            'over max_age and skew'           => [self::NOW - 361, 300, 60, $expired],
            'just over max_age and skew'      => [self::NOW - 360.00001, 300, 60, $expired],
            'at max_age, no skew'             => [self::NOW - 300, 300, 0, null],
            'over max_age, no skew'           => [self::NOW - 301, 300, 0, $expired],
            'just over max_age, no skew'      => [self::NOW - 300.00001, 300, 0, $expired],
            'max_age 1, at it and the skew'   => [self::NOW - 61, 1, 60, null],
            'max_age 1, over it and the skew' => [self::NOW - 62, 1, 60, $expired],
            'in the future, within skew'      => [self::NOW + 10, 300, 60, null],
        ];
    }

    /**
     * An `auth_time` older than `max_age` and the skew is
     * `authentication_expired`.
     *
     * @param  float|int  $time
     * @param  int  $maxAge
     * @param  int  $skew
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideOldTimes')]
    public function testATimeOlderThanMaxAgeIsExpired(float|int $time, int $maxAge, int $skew, ?FailureReason $reason): void
    {
        self::assertSame($reason, AuthenticationTimeRules::refusal(['auth_time' => $time], self::at(self::NOW), $skew, $maxAge));
    }

    /**
     * Rows of `[auth_time, start, skew, reason]` for a `max_age` of 0: an
     * authentication made for the request passes however slow the callback.
     *
     * @return iterable<string, array{0: float|int, 1: int, 2: int, 3: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideAfreshTimes(): iterable
    {
        $expired = FailureReason::AUTHENTICATION_EXPIRED;
        $slow    = self::NOW - 3600;

        yield from [
            'fresh, callback now'                => [self::NOW, self::NOW, 60, null],
            'fresh, an hour before the callback' => [$slow, $slow, 60, null],
            'a second after the start, no skew'  => [$slow + 1, $slow, 0, null],
            'at the start and skew, slow'        => [$slow - 60, $slow, 60, null],
            'over the start and skew, slow'      => [$slow - 61, $slow, 60, $expired],
            'at the start, no skew, slow'        => [$slow, $slow, 0, null],
            'just before the start, no skew'     => [$slow - 0.00001, $slow, 0, $expired],
            'before a start that is now'         => [self::NOW - 61, self::NOW, 60, $expired],
            'in the future, within the skew'     => [self::NOW + 60, $slow, 60, null],
        ];
    }

    /**
     * A `max_age` of 0 is judged against the request's start, never against how
     * long the callback took: it is no callback-age check.
     *
     * @param  float|int  $time
     * @param  int  $start
     * @param  int  $skew
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideAfreshTimes')]
    public function testAMaxAgeOfZeroIsHeldToTheRequestNotTheCallback(float|int $time, int $start, int $skew, ?FailureReason $reason): void
    {
        self::assertSame($reason, AuthenticationTimeRules::refusal(['auth_time' => $time], self::at(self::NOW), $skew, 0, self::at($start)));
    }

    /**
     * A `max_age` of 0 alone sets no age, however old the `auth_time`, and
     * still needs one to be there; the future-time bound still holds.
     *
     * @return void
     */
    public function testAMaxAgeOfZeroAloneIsNoAgeCheck(): void
    {
        $now = self::at(self::NOW);

        self::assertNull(AuthenticationTimeRules::refusal(['auth_time' => self::NOW - 100000], $now, self::SKEW, 0));
        self::assertSame(FailureReason::ID_TOKEN_INVALID, AuthenticationTimeRules::refusal([], $now, self::SKEW, 0));
        self::assertSame(FailureReason::ASSERTION_EXPIRED, AuthenticationTimeRules::refusal(['auth_time' => self::NOW + 61], $now, self::SKEW, 0));
    }

    /**
     * With a moment to follow, an `auth_time` is required even with no
     * `max_age`.
     *
     * @return void
     */
    public function testAMomentToFollowRequiresATime(): void
    {
        self::assertSame(FailureReason::ID_TOKEN_INVALID, AuthenticationTimeRules::refusal([], self::at(self::NOW), self::SKEW, null, self::at(self::NOW)));
        self::assertSame(FailureReason::ID_TOKEN_INVALID, AuthenticationTimeRules::refusal(['iat' => self::NOW], self::at(self::NOW), self::SKEW, null, self::at(self::NOW)));
    }

    /**
     * With no `max_age` asked for, however old an `auth_time` passes.
     *
     * @return void
     */
    public function testNoMaxAgeLeavesAnOldTimeAlone(): void
    {
        self::assertNull(AuthenticationTimeRules::refusal(['auth_time' => 1], self::at(self::NOW), self::SKEW, null));
    }

    /**
     * Rows of `[auth_time, skew, reason]` around the request's start less the
     * skew, with no `max_age`.
     *
     * @return iterable<string, array{0: float|int, 1: int, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideReauthenticationTimes(): iterable
    {
        $expired = FailureReason::AUTHENTICATION_EXPIRED;
        $start   = self::NOW - 30;

        yield from [
            'the start'                      => [$start, 60, null],
            'under the start and skew'       => [$start - 59, 60, null],
            'at the start and skew'          => [$start - 60, 60, null],
            'over the start and skew'        => [$start - 61, 60, $expired],
            'just over the start and skew'   => [$start - 60.00001, 60, $expired],
            'at the start, no skew'          => [$start, 0, null],
            'just before the start, no skew' => [$start - 0.00001, 0, $expired],
            'a second early, no skew'        => [$start - 1, 0, $expired],
            'just after the start, no skew'  => [$start + 0.00001, 0, null],
        ];
    }

    /**
     * A reauthentication's `auth_time` must not be earlier than the request's
     * start, less the skew.
     *
     * @param  float|int  $time
     * @param  int  $skew
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideReauthenticationTimes')]
    public function testAReauthenticationNeedsATimeNoEarlierThanItsStart(float|int $time, int $skew, ?FailureReason $reason): void
    {
        self::assertSame($reason, AuthenticationTimeRules::refusal(['auth_time' => $time], self::at(self::NOW), $skew, null, self::at(self::NOW - 30)));
    }

    /**
     * Each rule has its own answer: a time in the future refuses before the
     * start and `max_age` are read, and either of those refuses alone.
     *
     * @return void
     */
    public function testEachRuleAnswersForItself(): void
    {
        $now   = self::at(self::NOW);
        $start = self::at(self::NOW);

        self::assertSame(FailureReason::ASSERTION_EXPIRED, AuthenticationTimeRules::refusal(['auth_time' => self::NOW + 61], $now, self::SKEW, 0, $start));
        self::assertSame(FailureReason::AUTHENTICATION_EXPIRED, AuthenticationTimeRules::refusal(['auth_time' => self::NOW - 61], $now, self::SKEW, 0, $start));
        self::assertSame(FailureReason::AUTHENTICATION_EXPIRED, AuthenticationTimeRules::refusal(['auth_time' => self::NOW - 61], $now, self::SKEW, 1000, $start));
        self::assertSame(FailureReason::AUTHENTICATION_EXPIRED, AuthenticationTimeRules::refusal(['auth_time' => self::NOW - 62], $now, self::SKEW, 1, self::at(self::NOW - 1000)));
        self::assertNull(AuthenticationTimeRules::refusal(['auth_time' => self::NOW - 61], $now, self::SKEW, 0, self::at(self::NOW - 1000)));
        self::assertNull(AuthenticationTimeRules::refusal(['auth_time' => self::NOW - 60], $now, self::SKEW, 0, $start));
    }

    /**
     * Now is read to the microsecond, not to the second.
     *
     * @return void
     */
    public function testNowIsReadAtFullPrecision(): void
    {
        $now = self::at(self::NOW + 0.5);

        self::assertNull(AuthenticationTimeRules::refusal(['auth_time' => self::NOW + 60.5], $now, self::SKEW, null));
        self::assertSame(FailureReason::ASSERTION_EXPIRED, AuthenticationTimeRules::refusal(['auth_time' => self::NOW + 60.6], $now, self::SKEW, null));
        self::assertNull(AuthenticationTimeRules::refusal(['auth_time' => self::NOW - 60.5], $now, self::SKEW, 1));
        self::assertSame(FailureReason::AUTHENTICATION_EXPIRED, AuthenticationTimeRules::refusal(['auth_time' => self::NOW - 60.6], $now, self::SKEW, 1));
        self::assertNull(AuthenticationTimeRules::refusal(['auth_time' => self::NOW - 59.5], $now, self::SKEW, null, self::at(self::NOW + 0.5)));
        $claims = ['auth_time' => self::NOW - 59.6];

        self::assertSame(FailureReason::AUTHENTICATION_EXPIRED, AuthenticationTimeRules::refusal($claims, $now, self::SKEW, null, self::at(self::NOW + 0.5)));
    }

    /**
     * `iat` never decides, however old or new it is.
     *
     * @return void
     */
    public function testIatNeverStandsInForTheTime(): void
    {
        $now = self::at(self::NOW);

        self::assertNull(AuthenticationTimeRules::refusal(['auth_time' => self::NOW, 'iat' => 1], $now, self::SKEW, 1));
        self::assertSame(FailureReason::AUTHENTICATION_EXPIRED, AuthenticationTimeRules::refusal(['auth_time' => 1, 'iat' => self::NOW], $now, self::SKEW, 1));
    }

    /**
     * Calls in a row each see their own clock and skew.
     *
     * @return void
     */
    public function testCallsInARowEachSeeTheirOwnClockAndSkew(): void
    {
        $claims = ['auth_time' => self::NOW + 30];

        self::assertNull(AuthenticationTimeRules::refusal($claims, self::at(self::NOW), 60, null));
        self::assertSame(FailureReason::ASSERTION_EXPIRED, AuthenticationTimeRules::refusal($claims, self::at(self::NOW), 0, null));
        self::assertNull(AuthenticationTimeRules::refusal($claims, self::at(self::NOW + 30), 0, null));
        self::assertNull(AuthenticationTimeRules::refusal($claims, self::at(self::NOW), 60, null));
    }

    /**
     * The instant, to the microsecond.
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
