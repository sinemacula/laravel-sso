<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\TransitionReceipt;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;

/**
 * Unit tests for how a driver judged a response.
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
     * A verified completion carries its claims and no reason.
     *
     * @return void
     */
    public function testAVerifiedCompletionCarriesItsClaims(): void
    {
        $claims     = new VerifiedClaims('https://idp.example.com', 'subject-1', null, [], new AuthenticationContext);
        $completion = Completion::verified($claims);

        self::assertTrue($completion->isVerified());
        self::assertFalse($completion->isRefused());
        self::assertSame($claims, $completion->claims);
        self::assertNull($completion->reason);
    }

    /**
     * A refused completion carries its reason and no claims.
     *
     * @return void
     */
    public function testARefusedCompletionCarriesItsReason(): void
    {
        $completion = Completion::refused(FailureReason::SIGNATURE_INVALID);

        self::assertTrue($completion->isRefused());
        self::assertFalse($completion->isVerified());
        self::assertSame(FailureReason::SIGNATURE_INVALID, $completion->reason);
        self::assertNull($completion->claims);
    }

    /**
     * A verified completion takes a receipt and keeps its claims and replay.
     *
     * @return void
     */
    public function testAVerifiedCompletionTakesAReceipt(): void
    {
        $claims     = new VerifiedClaims('https://idp.example.com', 'subject-1', null, [], new AuthenticationContext);
        $replay     = ReplayRecord::samlAssertion('c', 'https://idp.example.com', '_a1', CarbonImmutable::parse('2026-11-01T10:05:00Z'));
        $receipt    = new TransitionReceipt('c', 'request-1', 4, 5, 7);
        $completion = Completion::verified($claims, $replay);
        $received   = $completion->withReceipt($receipt);

        self::assertNotSame($completion, $received);
        self::assertNull($completion->receipt);
        self::assertSame($receipt, $received->receipt);
        self::assertSame($claims, $received->claims);
        self::assertSame($replay, $received->replay);
        self::assertTrue($received->isVerified());
        self::assertSame($completion, $completion->withReceipt(null));
    }

    /**
     * A refusal ignores a receipt.
     *
     * @return void
     */
    public function testARefusalIgnoresAReceipt(): void
    {
        $completion = Completion::refused(FailureReason::SIGNATURE_INVALID);

        self::assertSame($completion, $completion->withReceipt(new TransitionReceipt('c', 'request-1', 4, 5, 7)));
    }
}
