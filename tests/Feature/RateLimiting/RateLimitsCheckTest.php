<?php

declare(strict_types = 1);

namespace Tests\Feature\RateLimiting;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\RateLimiting\RateLimitsCheck;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for the `[rate_limits]` configuration check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RateLimitsCheck::class)]
final class RateLimitsCheckTest extends TestCase
{
    use RunsConfigurationChecks;

    /** @var string The problem a malformed limit is reported with, for its key. */
    private const string MALFORMED = '`sso.rate_limits.%s` must be an array of `max` (1 to 1000000) and `decay_seconds` (1 to 86400).';

    /** @var string The problem one uncounted limit is reported with, for its key. */
    private const string UNCOUNTED = 'Remove `sso.rate_limits.%s`: the package counts no such limit, so it limits nothing.';

    /**
     * Not checked while the package is not in use, however malformed.
     *
     * @return void
     */
    public function testDoesNotApplyWhileThePackageIsNotInUse(): void
    {
        config()->set('sso.rate_limits.redemption', null);
        config()->set('sso.rate_limits.redemption.per_connection', ['max' => 1, 'decay_seconds' => 1]);

        self::assertNull($this->problemsOf(RateLimitsCheck::class));
    }

    /**
     * The shipped limits pass once the package is in use.
     *
     * @return void
     */
    public function testTheShippedLimitsPass(): void
    {
        $this->useThePackage();

        self::assertSame([], $this->problemsOf(RateLimitsCheck::class));
    }

    /**
     * A malformed protocol switch counts as in use, so the limits are checked.
     *
     * @return void
     */
    public function testAppliesOverAMalformedProtocolSwitch(): void
    {
        config()->set('sso.features.oidc', 'yes');
        config()->set('sso.rate_limits.metadata.per_connection', ['max' => 0, 'decay_seconds' => 3600]);

        self::assertSame([sprintf(self::MALFORMED, 'metadata.per_connection')], $this->problemsOf(RateLimitsCheck::class));
    }

    /**
     * Rows of `[setting, value, problems]`: changes to the limits and their
     * problems.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: list<string>}>
     */
    public static function provideProblems(): iterable
    {
        yield from [
            'a null limit' => [
                'sso.rate_limits.authorization_request.per_ip',
                null,
                [sprintf(self::MALFORMED, 'authorization_request.per_ip')],
            ],
            'a second scope over its range' => [
                'sso.rate_limits.authorization_request.per_email_domain',
                ['max' => 1000001, 'decay_seconds' => 60],
                [sprintf(self::MALFORMED, 'authorization_request.per_email_domain')],
            ],
            'no window' => [
                'sso.rate_limits.completion.per_connection',
                ['max' => 600, 'decay_seconds' => 0],
                [sprintf(self::MALFORMED, 'completion.per_connection')],
            ],
            'a missing limit' => [
                'sso.rate_limits.completion',
                ['per_ip' => ['max' => 30, 'decay_seconds' => 60]],
                [sprintf(self::MALFORMED, 'completion.per_connection')],
            ],
            'a null flow' => [
                'sso.rate_limits.redemption',
                null,
                [sprintf(self::MALFORMED, 'redemption.per_ip')],
            ],
            'a window over a day' => [
                'sso.rate_limits.metadata.per_connection',
                ['max' => 10, 'decay_seconds' => 86401],
                [sprintf(self::MALFORMED, 'metadata.per_connection')],
            ],
            'a malformed string' => [
                'sso.rate_limits.domain_check.per_connection',
                ['max' => 'thirty', 'decay_seconds' => 3600],
                [sprintf(self::MALFORMED, 'domain_check.per_connection')],
            ],
            'a scope its flow does not count' => [
                'sso.rate_limits.redemption.per_connection',
                ['max' => 30, 'decay_seconds' => 60],
                [sprintf(self::UNCOUNTED, 'redemption.per_connection')],
            ],
            'a scope the package does not have' => [
                'sso.rate_limits.metadata.per_tenant',
                ['max' => 30, 'decay_seconds' => 60],
                [sprintf(self::UNCOUNTED, 'metadata.per_tenant')],
            ],
            'a flow the package does not have' => [
                'sso.rate_limits.sign_in',
                ['per_ip' => ['max' => 30, 'decay_seconds' => 60]],
                [sprintf(self::UNCOUNTED, 'sign_in')],
            ],
            'a misspelt flow' => [
                'sso.rate_limits.authorisation_request',
                [],
                [sprintf(self::UNCOUNTED, 'authorisation_request')],
            ],
            'a canonical decimal string' => [
                'sso.rate_limits.redemption.per_ip',
                ['max' => '30', 'decay_seconds' => '60'],
                [],
            ],
            'a renamed table'       => ['sso.rate_limits.table', 'counters', []],
            'a counters connection' => ['sso.rate_limits.connection', 'counters', []],
        ];
    }

    /**
     * Each change reports exactly its problems.
     *
     * @param  string  $setting
     * @param  mixed  $value
     * @param  list<string>  $problems
     * @return void
     */
    #[DataProvider('provideProblems')]
    public function testReportsEachProblem(string $setting, mixed $value, array $problems): void
    {
        $this->useThePackage();

        config()->set($setting, $value);

        self::assertSame($problems, $this->problemsOf(RateLimitsCheck::class));
    }

    /**
     * Every problem across every flow is reported in one run.
     *
     * @return void
     */
    public function testReportsEveryProblemInOneRun(): void
    {
        $this->useThePackage();

        config()->set('sso.rate_limits.authorization_request.per_ip', null);
        config()->set('sso.rate_limits.completion.per_ip', ['max' => 0, 'decay_seconds' => 60]);
        config()->set('sso.rate_limits.redemption.per_ip', ['max' => 30]);
        config()->set('sso.rate_limits.metadata', 'often');
        config()->set('sso.rate_limits.domain_check.per_connection', []);
        config()->set('sso.rate_limits.redemption.per_email_domain', ['max' => 1, 'decay_seconds' => 1]);
        config()->set('sso.rate_limits.metadata_refresh', null);

        self::assertSame([
            sprintf(self::MALFORMED, 'authorization_request.per_ip'),
            sprintf(self::MALFORMED, 'completion.per_ip'),
            sprintf(self::MALFORMED, 'redemption.per_ip'),
            sprintf(self::MALFORMED, 'metadata.per_connection'),
            sprintf(self::MALFORMED, 'domain_check.per_connection'),
            'Remove `sso.rate_limits.redemption.per_email_domain`, `sso.rate_limits.metadata_refresh`: the package counts no such limits, so they limit nothing.',
        ], $this->problemsOf(RateLimitsCheck::class));
    }

    /**
     * A limits block that is not a block reports every flow's limits missing.
     *
     * @return void
     */
    public function testReportsALimitsBlockThatIsNotABlock(): void
    {
        $this->useThePackage();

        config()->set('sso.rate_limits', 'on');

        self::assertSame([
            sprintf(self::MALFORMED, 'authorization_request.per_ip'),
            sprintf(self::MALFORMED, 'completion.per_ip'),
            sprintf(self::MALFORMED, 'redemption.per_ip'),
            sprintf(self::MALFORMED, 'metadata.per_connection'),
            sprintf(self::MALFORMED, 'domain_check.per_connection'),
        ], $this->problemsOf(RateLimitsCheck::class));
    }
}
