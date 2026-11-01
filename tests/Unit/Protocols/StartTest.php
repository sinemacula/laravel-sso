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
 * keeps, typed, or refused with a reason, each outcome with only its own
 * payload.
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
     * A started request carries its navigation and what the request keeps, and
     * no reason; what it does not give is empty.
     *
     * @return void
     */
    public function testAStartedRequestNavigates(): void
    {
        $navigation = Navigation::redirect('https://idp.example.com/sso');
        $start      = Start::navigate($navigation, '_abc', 'https://idp.example.com', true);

        self::assertTrue($start->isNavigating());
        self::assertFalse($start->isRefused());
        self::assertSame($navigation, $start->navigation);
        self::assertSame('_abc', $start->samlRequestId);
        self::assertSame('https://idp.example.com', $start->expectedIssuer);
        self::assertTrue($start->issuerRequired);
        self::assertNull($start->reason);

        $bare = Start::navigate($navigation);

        self::assertNull($bare->samlRequestId);
        self::assertNull($bare->expectedIssuer);
        self::assertFalse($bare->issuerRequired);
    }

    /**
     * A SAML request id is at most 255 bytes, and neither it nor the expected
     * issuer may be empty.
     *
     * @return void
     */
    public function testRefusesAMalformedRequestBinding(): void
    {
        $navigation = Navigation::redirect('https://idp.example.com/sso');

        self::assertSame(str_repeat('a', 255), Start::navigate($navigation, str_repeat('a', 255))->samlRequestId);

        foreach ([[str_repeat('a', 256), null], ['', null], [null, '']] as [$id, $issuer]) {
            try {
                Start::navigate($navigation, $id, $issuer);
                self::fail('A malformed request binding was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertNotSame('', $exception->getMessage());
            }
        }
    }

    /**
     * A refused request carries its reason, and nothing else.
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
        self::assertNull($start->samlRequestId);
        self::assertNull($start->expectedIssuer);
        self::assertFalse($start->issuerRequired);
    }
}
