<?php

declare(strict_types = 1);

namespace Tests\Unit\Domains\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;

/**
 * Unit tests for the domain recheck outcome enum.
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
     * The values are these, in this order.
     *
     * @return void
     */
    public function testTheValuesAreStable(): void
    {
        self::assertSame(
            ['confirmed', 'restored', 'suspended', 'still_failing', 'lapsed', 'lookup_failed', 'resolver_threw', 'skipped'],
            array_column(RecheckOutcome::cases(), 'value'),
        );
    }

    /**
     * Every outcome but confirmed, restored and skipped is a failure.
     *
     * @return void
     */
    public function testOnlyTheFailuresAreFailures(): void
    {
        $failures = array_filter(RecheckOutcome::cases(), static fn (RecheckOutcome $outcome): bool => $outcome->isFailure());

        self::assertSame(
            [RecheckOutcome::SUSPENDED, RecheckOutcome::STILL_FAILING, RecheckOutcome::LAPSED, RecheckOutcome::LOOKUP_FAILED, RecheckOutcome::RESOLVER_THREW],
            array_values($failures),
        );
    }
}
