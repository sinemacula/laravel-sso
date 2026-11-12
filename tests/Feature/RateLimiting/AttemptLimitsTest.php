<?php

declare(strict_types = 1);

namespace Tests\Feature\RateLimiting;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\RateLimiting\AttemptLimit;
use SineMacula\Laravel\Sso\RateLimiting\AttemptLimits;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow;
use Tests\TestCase;

/**
 * Feature tests for each flow's attempt limits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptLimits::class)]
final class AttemptLimitsTest extends TestCase
{
    /** @var string The message a malformed `completion.per_ip` is refused with. */
    private const string MALFORMED = '`sso.rate_limits.completion.per_ip` must be an array of `max` (1 to 1000000) and `decay_seconds` (1 to 86400).';

    /**
     * Rows of `[flow, limits]`: shipped limits by scope as `[max, decay
     * seconds]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow, 1: array<string, array{0: int, 1: int}>}>
     */
    public static function provideDefaults(): iterable
    {
        yield from [
            'authorisation requests' => [AttemptFlow::AUTHORIZATION_REQUEST, ['per_ip' => [30, 60], 'per_email_domain' => [300, 60]]],
            'completions'            => [AttemptFlow::COMPLETION, ['per_ip' => [30, 60], 'per_connection' => [600, 60]]],
            'redemptions'            => [AttemptFlow::REDEMPTION, ['per_ip' => [30, 60]]],
            'metadata'               => [AttemptFlow::METADATA, ['per_connection' => [10, 3600]]],
            'domain checks'          => [AttemptFlow::DOMAIN_CHECK, ['per_connection' => [30, 3600]]],
        ];
    }

    /**
     * Each flow ships a limit for each of its scopes, in scope order.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow  $flow
     * @param  array<string, array{0: int, 1: int}>  $expected
     * @return void
     */
    #[DataProvider('provideDefaults')]
    public function testShipsALimitForEachScopeOfEachFlow(AttemptFlow $flow, array $expected): void
    {
        self::assertSame($expected, self::summarize($this->limits()->for($flow)));
    }

    /**
     * The limits are read on every call, so a change applies to the next one.
     *
     * @return void
     */
    public function testReadsTheLimitsOnEveryCall(): void
    {
        $limits = $this->limits();

        self::assertSame(['per_ip' => [30, 60]], self::summarize($limits->for(AttemptFlow::REDEMPTION)));

        config()->set('sso.rate_limits.redemption.per_ip', ['max' => 5, 'decay_seconds' => 300]);

        self::assertSame(['per_ip' => [5, 300]], self::summarize($limits->for(AttemptFlow::REDEMPTION)));
    }

    /**
     * Decimal strings from `env()` are read as integers at each bound.
     *
     * @return void
     */
    public function testReadsDecimalStringsAtEachBound(): void
    {
        config()->set('sso.rate_limits.completion.per_ip', ['max' => '1', 'decay_seconds' => '86400']);
        config()->set('sso.rate_limits.completion.per_connection', ['decay_seconds' => 1, 'max' => '1000000']);

        self::assertSame(['per_ip' => [1, 86400], 'per_connection' => [1000000, 1]], self::summarize($this->limits()->for(AttemptFlow::COMPLETION)));
    }

    /**
     * A key the flow is not counted in is not read as one of its limits.
     *
     * @return void
     */
    public function testReadsOnlyTheScopesOfTheFlow(): void
    {
        config()->set('sso.rate_limits.redemption.per_connection', 'anything');

        self::assertSame(['per_ip' => [30, 60]], self::summarize($this->limits()->for(AttemptFlow::REDEMPTION)));
    }

    /**
     * Rows of `[value]`: limits that are malformed.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedLimits(): iterable
    {
        yield from [
            'null'                  => [null],
            'an integer'            => [30],
            'a string'              => ['30/60'],
            'an empty array'        => [[]],
            'a list'                => [[30, 60]],
            'no max'                => [['decay_seconds' => 60]],
            'no decay'              => [['max' => 30]],
            'an extra key'          => [['max' => 30, 'decay_seconds' => 60, 'burst' => 5]],
            'a misspelt key'        => [['max' => 30, 'decay' => 60]],
            'no attempts'           => [['max' => 0, 'decay_seconds' => 60]],
            'negative attempts'     => [['max' => -1, 'decay_seconds' => 60]],
            'more than a million'   => [['max' => 1000001, 'decay_seconds' => 60]],
            'no window'             => [['max' => 30, 'decay_seconds' => 0]],
            'a negative window'     => [['max' => 30, 'decay_seconds' => -60]],
            'longer than a day'     => [['max' => 30, 'decay_seconds' => 86401]],
            'a null max'            => [['max' => null, 'decay_seconds' => 60]],
            'a null decay'          => [['max' => 30, 'decay_seconds' => null]],
            'a decimal string'      => [['max' => '1.5', 'decay_seconds' => 60]],
            'a padded string'       => [['max' => ' 30', 'decay_seconds' => 60]],
            'a signed string'       => [['max' => 30, 'decay_seconds' => '+60']],
            'an empty string'       => [['max' => '', 'decay_seconds' => 60]],
            'a float'               => [['max' => 30.0, 'decay_seconds' => 60]],
            'a boolean'             => [['max' => true, 'decay_seconds' => 60]],
            'an overflowing string' => [['max' => '99999999999999999999', 'decay_seconds' => 60]],
        ];
    }

    /**
     * A malformed limit fails closed, naming its key.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedLimits')]
    public function testRefusesAMalformedLimit(mixed $value): void
    {
        config()->set('sso.rate_limits.completion.per_ip', $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MALFORMED);

        $this->limits()->for(AttemptFlow::COMPLETION);
    }

    /**
     * A limit missing from its flow's block fails closed, naming its key.
     *
     * @return void
     */
    public function testRefusesAMissingLimit(): void
    {
        config()->set('sso.rate_limits.completion', ['per_connection' => ['max' => 600, 'decay_seconds' => 60]]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MALFORMED);

        $this->limits()->for(AttemptFlow::COMPLETION);
    }

    /**
     * Rows of `[setting, value]`: blocks that leave out every completion limit.
     *
     * @return iterable<string, array{0: string, 1: mixed}>
     */
    public static function provideMissingBlocks(): iterable
    {
        yield from [
            'a null flow'                => ['sso.rate_limits.completion', null],
            'a flow that is not a block' => ['sso.rate_limits.completion', 'on'],
            'no flows at all'            => ['sso.rate_limits', ['table' => 'sso_rate_limits']],
            'a null limits block'        => ['sso.rate_limits', null],
        ];
    }

    /**
     * A missing or malformed block fails closed at the first limit.
     *
     * @param  string  $setting
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMissingBlocks')]
    public function testRefusesAMissingBlock(string $setting, mixed $value): void
    {
        config()->set($setting, $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MALFORMED);

        $this->limits()->for(AttemptFlow::COMPLETION);
    }

    /**
     * A malformed second scope is refused too, naming its own key.
     *
     * @return void
     */
    public function testRefusesAMalformedSecondScope(): void
    {
        config()->set('sso.rate_limits.authorization_request.per_email_domain', ['max' => 0, 'decay_seconds' => 60]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`sso.rate_limits.authorization_request.per_email_domain` must be an array of `max` (1 to 1000000) and `decay_seconds` (1 to 86400).');

        $this->limits()->for(AttemptFlow::AUTHORIZATION_REQUEST);
    }

    /**
     * The shipped limits validate.
     *
     * @return void
     */
    public function testValidatesTheShippedLimits(): void
    {
        $limits = $this->limits();

        $limits->validate();

        foreach (AttemptFlow::cases() as $flow) {
            self::assertCount(count($flow->scopes()), $limits->for($flow));
        }
    }

    /**
     * Validating reads every flow, the last one included.
     *
     * @return void
     */
    public function testValidatesEveryFlow(): void
    {
        config()->set('sso.rate_limits.domain_check.per_connection', ['max' => 30, 'decay_seconds' => 86401]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`sso.rate_limits.domain_check.per_connection` must be an array of `max` (1 to 1000000) and `decay_seconds` (1 to 86400).');

        $this->limits()->validate();
    }

    /**
     * The container's limits, reading the test application's configuration.
     *
     * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptLimits
     */
    private function limits(): AttemptLimits
    {
        $limits = $this->app?->make(AttemptLimits::class);

        self::assertInstanceOf(AttemptLimits::class, $limits);

        return $limits;
    }

    /**
     * The limits as `[max, decay seconds]`, by scope, in their order.
     *
     * @param  array<string, \SineMacula\Laravel\Sso\RateLimiting\AttemptLimit>  $limits
     * @return array<string, array{0: int, 1: int}>
     */
    private static function summarize(array $limits): array
    {
        return array_map(static fn (AttemptLimit $limit): array => [$limit->max, $limit->decaySeconds], $limits);
    }
}
