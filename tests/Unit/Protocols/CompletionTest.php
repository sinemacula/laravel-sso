<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Completion;

/**
 * Unit tests for how a driver judged a response: until the completion pipeline
 * adds a verified outcome, every completion is refused with its reason.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Completion::class)]
final class CompletionTest extends TestCase
{
    /**
     * A refused completion carries its reason.
     *
     * @return void
     */
    public function testARefusedCompletionCarriesItsReason(): void
    {
        $completion = Completion::refused(FailureReason::SIGNATURE_INVALID);

        self::assertTrue($completion->isRefused());
        self::assertSame(FailureReason::SIGNATURE_INVALID, $completion->reason);
    }
}
