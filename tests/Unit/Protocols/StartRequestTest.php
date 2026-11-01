<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * Unit tests for what a driver is given to start a flow: the protocol state is
 * held as secrets, so it never shows in a dump and the request cannot be
 * serialised.
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
     */
    public function testKeepsEveryPart(): void
    {
        $request = new StartRequest(Purpose::LINK, 'web', 'ref-1', new Secret('state-value'), new Secret('nonce-value'), new Secret('verifier-value'));

        self::assertSame(Purpose::LINK, $request->purpose);
        self::assertSame('web', $request->application);
        self::assertSame('ref-1', $request->reference);
        self::assertSame('state-value', $request->state->reveal());
        self::assertSame('nonce-value', $request->nonce?->reveal());
        self::assertSame('verifier-value', $request->codeVerifier?->reveal());

        $saml = new StartRequest(Purpose::SIGN_IN, 'web', 'ref-2', new Secret('relay'));

        self::assertNull($saml->nonce);
        self::assertNull($saml->codeVerifier);
    }

    /**
     * The protocol state never shows in a dump, and the request cannot be
     * serialised.
     *
     * @return void
     */
    public function testTheProtocolStateNeverLeaks(): void
    {
        $request = new StartRequest(Purpose::SIGN_IN, 'web', 'ref-1', new Secret('state-value'), new Secret('nonce-value'), new Secret('verifier-value'));

        $dump = print_r($request, true);

        self::assertStringNotContainsString('state-value', $dump);
        self::assertStringNotContainsString('nonce-value', $dump);
        self::assertStringNotContainsString('verifier-value', $dump);

        $this->expectException(\LogicException::class);

        serialize($request);
    }
}
