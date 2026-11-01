<?php

declare(strict_types = 1);

namespace Tests\Unit\RateLimiting;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;

/**
 * Unit tests for the limiter's answer: allowed, or rate limited with a wait of
 * at least a second.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptResult::class)]
final class AttemptResultTest extends TestCase
{
    /**
     * An allowed attempt carries no reason and no wait.
     *
     * @return void
     */
    public function testAnAllowedAttemptCarriesNothing(): void
    {
        $result = AttemptResult::allowed();

        self::assertTrue($result->isAllowed());
        self::assertFalse($result->isRateLimited());
        self::assertNull($result->reason);
        self::assertNull($result->retryAfter);
    }

    /**
     * A refused attempt carries `rate_limited` and its wait.
     *
     * @return void
     */
    public function testARefusedAttemptCarriesItsWait(): void
    {
        $result = AttemptResult::rateLimited(1);

        self::assertFalse($result->isAllowed());
        self::assertTrue($result->isRateLimited());
        self::assertSame(FailureReason::RATE_LIMITED, $result->reason);
        self::assertSame(1, $result->retryAfter);
    }

    /**
     * A wait shorter than a second is a caller's mistake.
     *
     * @return void
     */
    public function testRefusesAWaitShorterThanASecond(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A rate limited attempt waits at least one second.');

        AttemptResult::rateLimited(0);
    }
}
