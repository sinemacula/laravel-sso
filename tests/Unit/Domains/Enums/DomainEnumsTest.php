<?php

declare(strict_types = 1);

namespace Tests\Unit\Domains\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Domains\Enums\DnsLookupStatus;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure;

/**
 * Unit tests for the domain enums.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainState::class)]
#[CoversClass(DomainStatus::class)]
#[CoversClass(DnsLookupStatus::class)]
#[CoversClass(RecheckFailure::class)]
final class DomainEnumsTest extends TestCase
{
    /**
     * The values are these, in this order.
     *
     * @return void
     */
    public function testTheValuesAreStable(): void
    {
        self::assertSame(['pending', 'verified', 'lapsed'], array_column(DomainState::cases(), 'value'));
        self::assertSame(['claimed', 'verified', 'unchanged', 'removed', 'refused', 'invalid'], array_column(DomainStatus::cases(), 'value'));
        self::assertSame(['found', 'absent', 'lookup_failed'], array_column(DnsLookupStatus::cases(), 'value'));
        self::assertSame(['record_absent', 'record_changed', 'lookup_failed'], array_column(RecheckFailure::cases(), 'value'));
    }

    /**
     * Every status succeeds but `refused` and `invalid`.
     *
     * @return void
     */
    public function testOnlyRefusedAndInvalidAreNotSuccesses(): void
    {
        $succeeded = array_filter(DomainStatus::cases(), static fn (DomainStatus $status): bool => $status->isSucceeded());

        self::assertSame([DomainStatus::CLAIMED, DomainStatus::VERIFIED, DomainStatus::UNCHANGED, DomainStatus::REMOVED], array_values($succeeded));
    }

    /**
     * A missing or changed record proves it gone; a failed lookup does not.
     *
     * @return void
     */
    public function testOnlyARecordFailureProvesTheRecordGone(): void
    {
        self::assertTrue(RecheckFailure::RECORD_ABSENT->isRecordGone());
        self::assertTrue(RecheckFailure::RECORD_CHANGED->isRecordGone());
        self::assertFalse(RecheckFailure::LOOKUP_FAILED->isRecordGone());
    }
}
