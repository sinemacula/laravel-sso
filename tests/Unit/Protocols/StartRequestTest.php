<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * Unit tests for what a driver is given to start a flow.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StartRequest::class)]
final class StartRequestTest extends TestCase
{
    /**
     * Every part is kept as given, and the protocol state reads back only
     * through the secrets.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testKeepsEveryPart(): void
    {
        $reference = RequestReference::generate();
        $request   = new StartRequest(Purpose::LINK, 'web', $reference, new Secret('state-value'), new Secret('nonce-value'), new Secret('verifier-value'));

        self::assertSame(Purpose::LINK, $request->purpose);
        self::assertSame('web', $request->application);
        self::assertSame($reference, $request->reference);
        self::assertSame('state-value', $request->state->reveal());
        self::assertSame('nonce-value', $request->nonce?->reveal());
        self::assertSame('verifier-value', $request->codeVerifier?->reveal());

        $saml = new StartRequest(Purpose::SIGN_IN, 'web', RequestReference::generate(), new Secret('relay'));

        self::assertNull($saml->nonce);
        self::assertNull($saml->codeVerifier);
    }

    /**
     * The protocol state never shows in a dump, and the request cannot be
     * serialised.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheProtocolStateNeverLeaks(): void
    {
        $request = new StartRequest(Purpose::SIGN_IN, 'web', RequestReference::generate(), new Secret('state-value'), new Secret('nonce-value'), new Secret('verifier-value'));

        $dump = print_r($request, true);

        self::assertStringNotContainsString('state-value', $dump);
        self::assertStringNotContainsString('nonce-value', $dump);
        self::assertStringNotContainsString('verifier-value', $dump);

        $this->expectException(\LogicException::class);

        serialize($request);
    }
}
