<?php

declare(strict_types = 1);

namespace Tests\Unit\Domains\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;

/**
 * Unit tests for the outcome of a domain's scheduled check: each value is
 * stable once released, and the failures are a record gone, a lapse and a
 * failed lookup.
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
            ['confirmed', 'restored', 'suspended', 'still_failing', 'lapsed', 'lookup_failed', 'skipped'],
            array_column(RecheckOutcome::cases(), 'value'),
        );
    }

    /**
     * A suspension, a record still gone, a lapse and a failed lookup are
     * failures; a confirmation, a restoration and a skip are not.
     *
     * @return void
     */
    public function testOnlyTheFailuresAreFailures(): void
    {
        $failures = array_filter(RecheckOutcome::cases(), static fn (RecheckOutcome $outcome): bool => $outcome->isFailure());

        self::assertSame(
            [RecheckOutcome::SUSPENDED, RecheckOutcome::STILL_FAILING, RecheckOutcome::LAPSED, RecheckOutcome::LOOKUP_FAILED],
            array_values($failures),
        );
    }
}
