<?php

declare(strict_types = 1);

namespace Tests\Unit\Enforcement;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Enforcement\EnforcementResult;
use SineMacula\Laravel\Sso\Enforcement\EnforcementSummary;
use SineMacula\Laravel\Sso\Enforcement\Enums\EnforcementStatus;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * Unit tests for enforcement change results.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnforcementResult::class)]
#[CoversClass(EnforcementStatus::class)]
final class EnforcementResultTest extends TestCase
{
    /**
     * The statuses are exactly these, by value, and only two are successes.
     *
     * @return void
     */
    public function testTheStatusesAreStable(): void
    {
        self::assertSame(['updated', 'unchanged', 'refused', 'invalid'], array_column(EnforcementStatus::cases(), 'value'));
        self::assertSame(
            [true, true, false, false],
            array_map(static fn (EnforcementStatus $status): bool => $status->isSucceeded(), EnforcementStatus::cases()),
        );
    }

    /**
     * Each success carries the enforcement and says what it is.
     *
     * @return void
     */
    public function testEachSuccessCarriesTheEnforcement(): void
    {
        $summary = self::summary();

        $cases = [
            [EnforcementResult::updated($summary), EnforcementStatus::UPDATED, true],
            [EnforcementResult::unchanged($summary), EnforcementStatus::UNCHANGED, false],
        ];

        foreach ($cases as [$result, $status, $changed]) {
            self::assertSame($status, $result->status);
            self::assertSame($summary, $result->enforcement);
            self::assertTrue($result->isSucceeded());
            self::assertSame($changed, $result->isChanged());
            self::assertFalse($result->isRefused());
            self::assertFalse($result->isInvalid());
            self::assertNull($result->reason);
            self::assertSame([], $result->violations);
        }
    }

    /**
     * Rows of `[reason]`: each reason an enforcement change is refused for.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideRefusals(): iterable
    {
        foreach ([FailureReason::FEATURE_DISABLED, FailureReason::FRESHNESS_REQUIRED, FailureReason::COMPLETED_SIGN_IN_REQUIRED] as $reason) {
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
        $result = EnforcementResult::refused($reason);

        self::assertSame(EnforcementStatus::REFUSED, $result->status);
        self::assertSame($reason, $result->reason);
        self::assertNull($result->enforcement);
        self::assertSame([], $result->violations);
        self::assertTrue($result->isRefused());
        self::assertFalse($result->isSucceeded());
        self::assertFalse($result->isChanged());
        self::assertFalse($result->isInvalid());
    }

    /**
     * Every other reason is the caller's mistake.
     *
     * @return void
     */
    public function testAnyOtherReasonIsRefusedAsAnArgument(): void
    {
        $allowed = [FailureReason::FEATURE_DISABLED, FailureReason::FRESHNESS_REQUIRED, FailureReason::COMPLETED_SIGN_IN_REQUIRED];
        $others  = array_filter(FailureReason::cases(), static fn (FailureReason $reason): bool => !in_array($reason, $allowed, true));

        self::assertNotSame([], $others);

        foreach ($others as $reason) {
            try {
                EnforcementResult::refused($reason);
                self::fail(sprintf('A refusal for [%s] was accepted.', $reason->value));
            } catch (\InvalidArgumentException $exception) {
                self::assertStringContainsString($reason->value, $exception->getMessage());
            }
        }
    }

    /**
     * An invalid change carries its violations and `settings_invalid`.
     *
     * @return void
     */
    public function testAnInvalidChangeCarriesItsViolations(): void
    {
        $violations = [new SettingViolation('connection_ids', ViolationCode::REQUIRED), new SettingViolation('connection_ids.2', ViolationCode::UNKNOWN)];
        $result     = EnforcementResult::invalid($violations);

        self::assertSame(EnforcementStatus::INVALID, $result->status);
        self::assertSame(FailureReason::SETTINGS_INVALID, $result->reason);
        self::assertSame($violations, $result->violations);
        self::assertNull($result->enforcement);
        self::assertTrue($result->isInvalid());
        self::assertFalse($result->isSucceeded());
        self::assertFalse($result->isChanged());
        self::assertFalse($result->isRefused());
    }

    /**
     * An invalid change names at least one violation.
     *
     * @return void
     */
    public function testAnInvalidChangeNeedsAViolation(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        EnforcementResult::invalid([]);
    }

    /**
     * The encoding has snake_case keys for every outcome.
     *
     * @return void
     */
    public function testEncodesWithSnakeCaseKeys(): void
    {
        self::assertSame([
            'status'      => 'updated',
            'enforcement' => ['tenant_id' => 'tenant-1', 'enabled' => true, 'connection_ids' => ['01a'], 'version' => '01jbversion', 'changed_at' => null],
            'reason'      => null,
            'violations'  => [],
        ], EnforcementResult::updated(self::summary())->jsonSerialize());

        self::assertSame(
            ['status' => 'refused', 'enforcement' => null, 'reason' => 'completed_sign_in_required', 'violations' => []],
            EnforcementResult::refused(FailureReason::COMPLETED_SIGN_IN_REQUIRED)->jsonSerialize(),
        );

        self::assertSame(
            ['status' => 'invalid', 'enforcement' => null, 'reason' => 'settings_invalid', 'violations' => [['setting' => 'connection_ids.0', 'code' => 'invalid_type']]],
            EnforcementResult::invalid([new SettingViolation('connection_ids.0', ViolationCode::INVALID_TYPE)])->jsonSerialize(),
        );
    }

    /**
     * An enforcement that is on, satisfied by one connection.
     *
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementSummary
     */
    private static function summary(): EnforcementSummary
    {
        return new EnforcementSummary('tenant-1', true, ['01a'], '01jbversion');
    }
}
