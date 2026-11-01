<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Secrets\Secret;
use Tests\Fixtures\Secrets\CountingSecretEncrypter;

/**
 * Unit tests for the consumed request a driver validates against: every part
 * kept, the nonce matched against its digest in constant time, the PKCE
 * verifier decrypted only when asked for, afresh each time, and neither the
 * nonce, the PKCE verifier nor its ciphertext shown or serialised.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConsumedRequest::class)]
final class ConsumedRequestTest extends TestCase
{
    /** @var string The PKCE verifier's ciphertext, as the request stored it. */
    private const string CIPHERTEXT = 'encrypted:pkce-1';

    /**
     * Every part is kept; the nonce matches only its own digest.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testKeepsEveryPart(): void
    {
        $reference = RequestReference::generate();
        $started   = CarbonImmutable::parse('2026-11-01T10:00:00Z');
        $nonce     = hash('sha256', 'nonce-1');
        $request   = new ConsumedRequest(Purpose::REAUTHENTICATE, 'web', $reference, $started, 'https://op.example.com', true, '_id', $nonce, self::CIPHERTEXT, self::encrypter());

        self::assertSame(Purpose::REAUTHENTICATE, $request->purpose);
        self::assertSame('web', $request->application);
        self::assertSame($reference, $request->reference);
        self::assertSame($started, $request->startedAt);
        self::assertSame('https://op.example.com', $request->expectedIssuer);
        self::assertTrue($request->issuerRequired);
        self::assertSame('_id', $request->samlRequestId);
        self::assertSame('pkce-1', $request->codeVerifier()?->reveal());
        self::assertTrue($request->isNonce('nonce-1'));
        self::assertFalse($request->isNonce('nonce-2'));
        self::assertFalse($request->isNonce(''));
    }

    /**
     * A request with no nonce matches none, and keeps the defaults.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARequestWithNoNonceMatchesNone(): void
    {
        $request = new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::generate(), CarbonImmutable::now());

        self::assertFalse($request->isNonce(''));
        self::assertFalse($request->isNonce('nonce-1'));
        self::assertNull($request->expectedIssuer);
        self::assertFalse($request->issuerRequired);
        self::assertNull($request->samlRequestId);
        self::assertNull($request->codeVerifier());
    }

    /**
     * The PKCE verifier is decrypted only when asked for, afresh on each call,
     * into a secret of its own; a request with no ciphertext decrypts nothing,
     * whatever encrypter it is given.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testThePkceVerifierIsDecryptedOnlyWhenAskedFor(): void
    {
        $encrypter = new CountingSecretEncrypter(self::encrypter());
        $request   = new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::generate(), CarbonImmutable::now(), codeVerifier: self::CIPHERTEXT, encrypter: $encrypter);

        self::assertSame(0, $encrypter->decryptions);

        $first  = $request->codeVerifier();
        $second = $request->codeVerifier();

        self::assertSame(2, $encrypter->decryptions);
        self::assertInstanceOf(Secret::class, $first);
        self::assertSame('pkce-1', $first->reveal());
        self::assertSame('pkce-1', $second?->reveal());
        self::assertNotSame($first, $second);

        $bare = new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::generate(), CarbonImmutable::now(), encrypter: $encrypter);

        self::assertNull($bare->codeVerifier());
        self::assertSame(2, $encrypter->decryptions);
    }

    /**
     * A ciphertext no key decrypts is no failure until the verifier is asked
     * for, and then propagates.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACiphertextNoKeyDecryptsPropagatesWhenAskedFor(): void
    {
        $reference = RequestReference::generate();
        $request   = new ConsumedRequest(Purpose::SIGN_IN, 'web', $reference, CarbonImmutable::now(), codeVerifier: 'not a ciphertext', encrypter: self::encrypter());

        $this->expectExceptionObject(new \RuntimeException('The ciphertext cannot be decrypted.'));

        $request->codeVerifier();
    }

    /**
     * A ciphertext given with no encrypter to decrypt it is refused.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACiphertextWithNoEncrypterIsRefused(): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException('An encrypted PKCE verifier is given with the encrypter that decrypts it.'));

        new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::generate(), CarbonImmutable::now(), codeVerifier: self::CIPHERTEXT);
    }

    /**
     * A dump shows neither the nonce's digest nor the verifier.
     *
     * @return void
     */
    public function testNeverShowsItsSecrets(): void
    {
        $reference = RequestReference::fromString(str_repeat('r', 32));
        $nonce     = hash('sha256', 'nonce-1');
        $request   = new ConsumedRequest(Purpose::SIGN_IN, 'web', $reference, CarbonImmutable::now(), 'iss', false, null, $nonce, self::CIPHERTEXT, self::encrypter());

        self::assertSame([
            'purpose'         => 'sign_in',
            'application'     => 'web',
            'reference'       => str_repeat('r', 32),
            'expected_issuer' => 'iss',
            'issuer_required' => false,
            'saml_request_id' => null,
            'nonce'           => '[redacted]',
            'code_verifier'   => '[redacted]',
        ], $request->__debugInfo());
        self::assertStringNotContainsString(hash('sha256', 'nonce-1'), print_r($request, true));

        foreach (['pkce-1', self::CIPHERTEXT, 'encrypted:'] as $needle) {
            self::assertStringNotContainsString($needle, print_r($request, true));
            self::assertStringNotContainsString($needle, var_export((array) $request, true));
        }

        $bare = new ConsumedRequest(Purpose::SIGN_IN, 'web', $reference, CarbonImmutable::now());

        self::assertNull($bare->__debugInfo()['nonce']);
        self::assertNull($bare->__debugInfo()['code_verifier']);
    }

    /**
     * A consumed request cannot be serialised.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testCannotBeSerialised(): void
    {
        $this->expectExceptionObject(new \LogicException('A consumed authorisation request cannot be serialised.'));

        serialize(new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::generate(), CarbonImmutable::now()));
    }

    /**
     * A consumed request cannot be unserialised.
     *
     * @return void
     */
    public function testCannotBeUnserialised(): void
    {
        $this->expectExceptionObject(new \LogicException('A consumed authorisation request cannot be unserialised.'));

        unserialize('O:48:"SineMacula\Laravel\Sso\Protocols\ConsumedRequest":0:{}');
    }

    /**
     * An encrypter that prefixes a secret with `encrypted:`, and decrypts only
     * what carries the prefix.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SecretEncrypter
     */
    private static function encrypter(): SecretEncrypter
    {
        return new readonly class implements SecretEncrypter {
            /**
             * The secret, prefixed.
             *
             * @param  string  $secret
             * @return string
             */
            #[\Override]
            public function encrypt(#[\SensitiveParameter] string $secret): string
            {
                return 'encrypted:' . $secret;
            }

            /**
             * The secret the prefixed ciphertext holds.
             *
             * @param  string  $ciphertext
             * @return string
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function decrypt(string $ciphertext): string
            {
                if (!str_starts_with($ciphertext, 'encrypted:')) {
                    throw new \RuntimeException('The ciphertext cannot be decrypted.');
                }

                return substr($ciphertext, strlen('encrypted:'));
            }
        };
    }
}
