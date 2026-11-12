<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\Enums\CorrelationKind;

/**
 * Unit tests for what a driver read to find a response's request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Correlation::class)]
#[CoversClass(CorrelationKind::class)]
final class CorrelationTest extends TestCase
{
    /**
     * A solicited response carries its state, as a secret looked up by its
     * digest, and its SAML request id.
     *
     * @return void
     */
    public function testASolicitedResponse(): void
    {
        $correlation = Correlation::solicited('state-value', '_request-1');

        self::assertTrue($correlation->isSolicited());
        self::assertFalse($correlation->isUnsolicited());
        self::assertFalse($correlation->isUncorrelated());
        self::assertSame(CorrelationKind::SOLICITED, $correlation->kind);
        self::assertSame('state-value', $correlation->state?->reveal());
        self::assertSame(hash('sha256', 'state-value'), $correlation->stateDigest());
        self::assertSame('_request-1', $correlation->samlRequestId);
        self::assertStringNotContainsString('state-value', print_r($correlation, true));

        $oidc = Correlation::solicited('state-value');

        self::assertNull($oidc->samlRequestId);

        $saml = Correlation::solicited(null, '_request-1');

        self::assertNull($saml->state);
        self::assertNull($saml->stateDigest());
        self::assertSame('_request-1', Correlation::solicited('', '_request-1')->samlRequestId);
        self::assertNull(Correlation::solicited('state-value', '')->samlRequestId);
    }

    /**
     * A solicited response names its request somehow, by an id of at most 255
     * bytes.
     *
     * @return void
     */
    public function testASolicitedResponseNamesItsRequest(): void
    {
        self::assertSame(255, Correlation::MAX_REQUEST_ID_LENGTH);
        self::assertSame(str_repeat('a', 255), Correlation::solicited(null, str_repeat('a', 255))->samlRequestId);

        $messages = [];

        foreach ([[null, null], ['', ''], [null, str_repeat('a', 256)]] as [$state, $id]) {
            try {
                Correlation::solicited($state, $id);
                $messages[] = 'accepted';
            } catch (\InvalidArgumentException $exception) {
                $messages[] = $exception->getMessage();
            }
        }

        self::assertSame([
            'A solicited response names its request by its state or its SAML request id.',
            'A solicited response names its request by its state or its SAML request id.',
            'A SAML request id is at most 255 bytes.',
        ], $messages);
    }

    /**
     * An unsolicited or uncorrelated response carries nothing.
     *
     * @return void
     */
    public function testUnsolicitedAndUncorrelatedResponses(): void
    {
        $unsolicited  = Correlation::unsolicited();
        $uncorrelated = Correlation::uncorrelated();

        self::assertTrue($unsolicited->isUnsolicited());
        self::assertFalse($unsolicited->isSolicited());
        self::assertFalse($unsolicited->isUncorrelated());
        self::assertTrue($uncorrelated->isUncorrelated());
        self::assertFalse($uncorrelated->isSolicited());
        self::assertFalse($uncorrelated->isUnsolicited());

        foreach ([$unsolicited, $uncorrelated] as $correlation) {
            self::assertNull($correlation->state);
            self::assertNull($correlation->stateDigest());
            self::assertNull($correlation->samlRequestId);
        }

        self::assertSame(['solicited', 'unsolicited', 'uncorrelated'], array_column(CorrelationKind::cases(), 'value'));
    }

    /**
     * A correlation cannot be serialised: its state is a secret.
     *
     * @return void
     */
    public function testCannotBeSerialized(): void
    {
        $this->expectException(\LogicException::class);

        serialize(Correlation::solicited('state-value'));
    }
}
