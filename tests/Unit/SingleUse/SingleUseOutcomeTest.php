<?php

declare(strict_types = 1);

namespace Tests\Unit\SingleUse;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;

/**
 * Unit tests for the single-use store's outcomes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SingleUseOutcome::class)]
final class SingleUseOutcomeTest extends TestCase
{
    /**
     * The store answers `recorded` or `seen`, and nothing else.
     *
     * @return void
     */
    public function testTheOutcomesAreRecordedAndSeen(): void
    {
        self::assertSame(['recorded', 'seen'], array_column(SingleUseOutcome::cases(), 'value'));
    }
}
