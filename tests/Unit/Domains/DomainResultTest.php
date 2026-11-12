<?php

declare(strict_types = 1);

namespace Tests\Unit\Domains;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Domains\DomainResult;
use SineMacula\Laravel\Sso\Domains\DomainSummary;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * Unit tests for domain operation results.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainResult::class)]
#[CoversClass(DomainStatus::class)]
final class DomainResultTest extends TestCase
{
    /** @var string The token the summary carries. */
    private const string TOKEN = 'the-verification-token';

    /**
     * Each success carries its summary and says what it is.
     *
     * @return void
     */
    public function testEachSuccessCarriesItsSummary(): void
    {
        $summary = self::summary();

        $cases = [
            [DomainResult::claimed($summary), DomainStatus::CLAIMED, true],
            [DomainResult::verified($summary), DomainStatus::VERIFIED, true],
            [DomainResult::unchanged($summary), DomainStatus::UNCHANGED, false],
            [DomainResult::removed($summary), DomainStatus::REMOVED, true],
        ];

        foreach ($cases as [$result, $status, $changed]) {
            self::assertSame($status, $result->status);
            self::assertSame($summary, $result->domain);
            self::assertTrue($result->isSucceeded());
            self::assertSame($changed, $result->isChanged());
            self::assertFalse($result->isRefused());
            self::assertFalse($result->isInvalid());
            self::assertFalse($result->isRateLimited());
            self::assertNull($result->reason);
            self::assertNull($result->retryAfter);
        }
    }

    /**
     * Rows of `[reason]`: each reason a domain operation is refused for.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideRefusals(): iterable
    {
        $reasons = [
            FailureReason::FRESHNESS_REQUIRED, FailureReason::CONNECTION_NOT_FOUND, FailureReason::DOMAIN_NOT_FOUND, FailureReason::DOMAIN_UNAVAILABLE,
            FailureReason::DOMAIN_CLAIM_EXPIRED, FailureReason::DOMAIN_RECORD_NOT_FOUND, FailureReason::DOMAIN_LOOKUP_FAILED,
        ];

        foreach ($reasons as $reason) {
            yield $reason->value => [$reason];
        }
    }

    /**
     * A refusal carries its reason and nothing else.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testARefusalCarriesItsReason(FailureReason $reason): void
    {
        $result = DomainResult::refused($reason);

        self::assertSame(DomainStatus::REFUSED, $result->status);
        self::assertSame($reason, $result->reason);
        self::assertTrue($result->isRefused());
        self::assertFalse($result->isSucceeded());
        self::assertFalse($result->isChanged());
        self::assertFalse($result->isRateLimited());
        self::assertNull($result->domain);
    }

    /**
     * Any other reason is the caller's mistake.
     *
     * @return void
     */
    public function testRefusesAReasonOfAnotherOperation(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        DomainResult::refused(FailureReason::KEY_STATE_CONFLICT);
    }

    /**
     * Throttling is a `rate_limited` refusal with at least one second to wait.
     *
     * @return void
     */
    public function testThrottlingIsAnOutcome(): void
    {
        $result = DomainResult::rateLimited(30);

        self::assertTrue($result->isRefused());
        self::assertTrue($result->isRateLimited());
        self::assertSame(FailureReason::RATE_LIMITED, $result->reason);
        self::assertSame(30, $result->retryAfter);

        $this->expectException(\InvalidArgumentException::class);

        DomainResult::rateLimited(0);
    }

    /**
     * An invalid result carries `settings_invalid` and at least one violation.
     *
     * @return void
     */
    public function testAnInvalidResultCarriesItsViolations(): void
    {
        $violation = new SettingViolation('domain', ViolationCode::NOT_ALLOWED);
        $result    = DomainResult::invalid([$violation]);

        self::assertSame(DomainStatus::INVALID, $result->status);
        self::assertTrue($result->isInvalid());
        self::assertFalse($result->isSucceeded());
        self::assertSame(FailureReason::SETTINGS_INVALID, $result->reason);
        self::assertSame([$violation], $result->violations);

        $this->expectException(\InvalidArgumentException::class);

        DomainResult::invalid([]);
    }

    /**
     * The encoding has snake_case keys and never the token.
     *
     * @return void
     */
    public function testEncodesWithoutTheToken(): void
    {
        $claimed = DomainResult::claimed(self::summary());
        $invalid = DomainResult::invalid([new SettingViolation('domain', ViolationCode::DUPLICATE)]);

        self::assertSame(['status', 'domain', 'reason', 'violations', 'retry_after'], array_keys($claimed->jsonSerialize()));
        self::assertStringNotContainsString(self::TOKEN, (string) json_encode($claimed));
        self::assertSame(
            ['status' => 'invalid', 'domain' => null, 'reason' => 'settings_invalid', 'violations' => [['setting' => 'domain', 'code' => 'duplicate']], 'retry_after' => null],
            $invalid->jsonSerialize(),
        );
        self::assertSame(
            ['status' => 'refused', 'domain' => null, 'reason' => 'rate_limited', 'violations' => [], 'retry_after' => 9],
            DomainResult::rateLimited(9)->jsonSerialize(),
        );
    }

    /**
     * A pending claim's summary.
     *
     * @return \SineMacula\Laravel\Sso\Domains\DomainSummary
     */
    private static function summary(): DomainSummary
    {
        return new DomainSummary(
            id: '01jbexampledomain000000000',
            connectionId: '01jbexampleconnection00000',
            domain: 'example.com',
            state: DomainState::PENDING,
            recordName: '_sso-verification.example.com',
            verificationToken: self::TOKEN,
            claimedAt: CarbonImmutable::parse('2026-11-01T09:30:00Z'),
            pendingExpiresAt: CarbonImmutable::parse('2026-11-08T09:30:00Z'),
        );
    }
}
