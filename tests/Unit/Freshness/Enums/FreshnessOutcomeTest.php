<?php

declare(strict_types = 1);

namespace Tests\Unit\Freshness\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;

/**
 * Unit tests for the freshness contract's outcomes: two, of which only `fresh`
 * lets an operation write.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FreshnessOutcome::class)]
final class FreshnessOutcomeTest extends TestCase
{
    /**
     * The contract answers `fresh` or `stale`, and nothing else.
     *
     * @return void
     */
    public function testTheOutcomesAreFreshAndStale(): void
    {
        self::assertSame(['fresh', 'stale'], array_column(FreshnessOutcome::cases(), 'value'));
    }

    /**
     * Only `fresh` is fresh.
     *
     * @return void
     */
    public function testOnlyFreshIsFresh(): void
    {
        self::assertTrue(FreshnessOutcome::FRESH->isFresh());
        self::assertFalse(FreshnessOutcome::STALE->isFresh());
    }
}
