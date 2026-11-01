<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Navigation;
use SineMacula\Laravel\Sso\Protocols\Start;

/**
 * Unit tests for how a driver started a flow: navigating with what the request
 * keeps, or refused with a reason, each outcome with only its own payload.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Start::class)]
final class StartTest extends TestCase
{
    /**
     * A started request carries its navigation and request data, and no reason.
     *
     * @return void
     */
    public function testAStartedRequestNavigates(): void
    {
        $navigation = Navigation::redirect('https://idp.example.com/sso');
        $start      = Start::navigate($navigation, ['request_id' => '_abc']);

        self::assertTrue($start->isNavigating());
        self::assertFalse($start->isRefused());
        self::assertSame($navigation, $start->navigation);
        self::assertSame(['request_id' => '_abc'], $start->requestData);
        self::assertNull($start->reason);
        self::assertSame([], Start::navigate($navigation)->requestData);
    }

    /**
     * A refused request carries its reason, and no navigation or data.
     *
     * @return void
     */
    public function testARefusedRequestCarriesItsReason(): void
    {
        $start = Start::refused(FailureReason::CONNECTION_UNAVAILABLE);

        self::assertTrue($start->isRefused());
        self::assertFalse($start->isNavigating());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $start->reason);
        self::assertNull($start->navigation);
        self::assertSame([], $start->requestData);
    }
}
