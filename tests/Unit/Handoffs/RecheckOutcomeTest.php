<?php

declare(strict_types = 1);

namespace Tests\Unit\Handoffs;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;

/**
 * Unit tests for what a handoff's recheck comes to: its four outcomes, their
 * stable values, and the failure reason each refusal reports.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecheckOutcome::class)]
final class RecheckOutcomeTest extends TestCase
{
    /**
     * The outcomes are these, in this order, with these values.
     *
     * @return void
     */
    public function testTheOutcomesAndTheirValues(): void
    {
        self::assertSame(
            [
                'passed', 'connection_unavailable', 'enforcement_unsatisfied', 'link_changed', 'link_suspended', 'principal_scope_unknown', 'link_reserved', 'link_ineligible',
                'independent_authentication_required', 'identity_mismatch', 'subject_already_linked', 'link_limit_reached', 'reservation_invalid',
                'freshness_required', 'session_ineligible', 'authentication_expired',
            ],
            array_map(static fn (RecheckOutcome $outcome): string => $outcome->value, RecheckOutcome::cases()),
        );
    }

    /**
     * Each outcome and the reason it reports.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function reasons(): iterable
    {
        yield 'passed' => [RecheckOutcome::PASSED, null];
        yield 'connection unavailable' => [RecheckOutcome::CONNECTION_UNAVAILABLE, FailureReason::CONNECTION_UNAVAILABLE];
        yield 'enforcement unsatisfied' => [RecheckOutcome::ENFORCEMENT_UNSATISFIED, FailureReason::ENFORCEMENT_UNSATISFIED];
        yield 'link changed' => [RecheckOutcome::LINK_CHANGED, FailureReason::LINK_CHANGED];
        yield 'link suspended' => [RecheckOutcome::LINK_SUSPENDED, FailureReason::LINK_SUSPENDED];
        yield 'principal scope unknown' => [RecheckOutcome::PRINCIPAL_SCOPE_UNKNOWN, FailureReason::PRINCIPAL_SCOPE_UNKNOWN];
        yield 'link reserved' => [RecheckOutcome::LINK_RESERVED, FailureReason::LINK_RESERVED];
        yield 'link ineligible' => [RecheckOutcome::LINK_INELIGIBLE, FailureReason::LINK_INELIGIBLE];
        yield 'identity mismatch' => [RecheckOutcome::IDENTITY_MISMATCH, FailureReason::IDENTITY_MISMATCH];
        yield 'subject already linked' => [RecheckOutcome::SUBJECT_ALREADY_LINKED, FailureReason::SUBJECT_ALREADY_LINKED];
        yield 'link limit reached' => [RecheckOutcome::LINK_LIMIT_REACHED, FailureReason::LINK_LIMIT_REACHED];
        yield 'independent authentication required' => [RecheckOutcome::INDEPENDENT_AUTHENTICATION_REQUIRED, FailureReason::INDEPENDENT_AUTHENTICATION_REQUIRED];
        yield 'reservation invalid' => [RecheckOutcome::RESERVATION_INVALID, FailureReason::RESERVATION_INVALID];
        yield 'freshness required' => [RecheckOutcome::FRESHNESS_REQUIRED, FailureReason::FRESHNESS_REQUIRED];
        yield 'session ineligible' => [RecheckOutcome::SESSION_INELIGIBLE, FailureReason::SESSION_INELIGIBLE];
        yield 'authentication expired' => [RecheckOutcome::AUTHENTICATION_EXPIRED, FailureReason::AUTHENTICATION_EXPIRED];
    }

    /**
     * Each outcome reports its reason, and a passed recheck none.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome  $outcome
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('reasons')]
    public function testEachOutcomeReportsItsReason(RecheckOutcome $outcome, ?FailureReason $reason): void
    {
        self::assertSame($reason, $outcome->reason());
    }

    /**
     * Each outcome is read back from its value.
     *
     * @return void
     */
    public function testEachOutcomeIsReadBackFromItsValue(): void
    {
        self::assertSame(RecheckOutcome::PASSED, RecheckOutcome::from('passed'));
        self::assertSame(RecheckOutcome::CONNECTION_UNAVAILABLE, RecheckOutcome::from('connection_unavailable'));
        self::assertSame(RecheckOutcome::ENFORCEMENT_UNSATISFIED, RecheckOutcome::from('enforcement_unsatisfied'));
        self::assertSame(RecheckOutcome::LINK_CHANGED, RecheckOutcome::from('link_changed'));
        self::assertNull(RecheckOutcome::tryFrom('PASSED'));
    }
}
