<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc\Jose;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ClientKey;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\JoseAdapter;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\JwsSigner;
use Tests\Concerns\TreatsWarningsAsErrors;

/**
 * Unit tests for the JOSE adapter's library calls (SSO-7.3, RFC 7523): every
 * allowed algorithm verifies a token signed by hand with OpenSSL (never by the
 * library), and nothing verifies once the signature, the payload, the key, the
 * algorithm or the allow-list is wrong; client assertions are signed with PS256
 * or ES256 and the claims RFC 7523 asks for, and verify without the library.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JoseAdapter::class)]
#[CoversClass(ClientKey::class)]
final class JoseAdapterTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /** @var array<string, \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey> The keys, generated once. */
    private static array $keys = [];

    /**
     * Rows of `[algorithm, key]`: every algorithm, with a key that fits it.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideAlgorithms(): iterable
    {
        foreach (['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'] as $algorithm) {
            yield $algorithm => [$algorithm, 'rsa'];
        }

        yield from ['ES256' => ['ES256', 'P-256'], 'ES384' => ['ES384', 'P-384'], 'ES512' => ['ES512', 'P-521']];
    }

    /**
     * A token signed by hand with each algorithm verifies with its key, and
     * fails once a byte of its signature or payload changes.
     *
     * @param  string  $algorithm
     * @param  string  $key
     * @return void
     *
     * @throws \LogicException
     */
    #[DataProvider('provideAlgorithms')]
    public function testEachAlgorithmVerifiesAHandSignedToken(string $algorithm, string $key): void
    {
        $signer  = self::key($key);
        $compact = JwsSigner::sign(['alg' => $algorithm, 'kid' => 'k'], ['sub' => 'a'], $signer);
        $allowed = AlgorithmAllowList::of([$algorithm]);
        $admit   = ProviderKey::admit($signer->jwk(), $allowed) ?? throw new \LogicException('The key was refused.');

        [$header, $payload, $signature] = explode('.', $compact);

        $flipped  = $signature[5] === 'A' ? 'B' : 'A';
        $tampered = $header . '.' . $payload . '.' . substr_replace($signature, $flipped, 5, 1);
        $other    = $header . '.' . JwsSigner::encode('{"sub":"b"}') . '.' . $signature;

        self::assertTrue((new JoseAdapter)->verify(self::read($compact), $admit, $allowed));
        self::assertFalse((new JoseAdapter)->verify(self::read($tampered), $admit, $allowed));
        self::assertFalse((new JoseAdapter)->verify(self::read($other), $admit, $allowed));
    }

    /**
     * A token signed with another key of the right type does not verify.
     *
     * @return void
     */
    public function testAnotherKeysSignatureDoesNotVerify(): void
    {
        $allowed = AlgorithmAllowList::of(['RS256']);
        $token   = self::read(JwsSigner::sign(['alg' => 'RS256'], ['sub' => 'a'], self::key('attacker')));

        self::assertFalse((new JoseAdapter)->verify($token, self::admitted('rsa', $allowed), $allowed));
    }

    /**
     * A key that does not fit the algorithm, or an algorithm off the
     * allow-list, never verifies, though the signature would.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testAKeyThatDoesNotFitNeverVerifies(): void
    {
        $adapter = new JoseAdapter;
        $rs256   = self::read(JwsSigner::sign(['alg' => 'RS256'], ['sub' => 'a'], self::key('rsa')));
        $es512   = self::read(JwsSigner::sign(['alg' => 'ES512'], ['sub' => 'a'], self::key('P-256')));
        $both    = AlgorithmAllowList::of(['RS256', 'PS256']);
        $pinned  = ProviderKey::admit(self::key('rsa')->jwk('PS256'), $both) ?? throw new \LogicException;

        self::assertFalse($adapter->verify($rs256, self::admitted('rsa', $both), AlgorithmAllowList::of(['PS256'])));
        self::assertFalse($adapter->verify($rs256, $pinned, $both));
        self::assertFalse($adapter->verify($es512, self::admitted('P-256', AlgorithmAllowList::of(['ES512'])), AlgorithmAllowList::of(['ES512'])));
        self::assertTrue($adapter->verify($rs256, self::admitted('rsa', $both), $both));
    }

    /**
     * An HMAC token signed with the key's public PEM never verifies: its
     * algorithm is off the allow-list, so it does not fit the key.
     *
     * @return void
     */
    public function testAnHmacTokenNeverVerifies(): void
    {
        $allowed = AlgorithmAllowList::of(['RS256']);
        $token   = self::read(JwsSigner::hmac(['alg' => 'HS256'], ['sub' => 'a'], self::key('rsa')->publicKeyPem));

        self::assertFalse((new JoseAdapter)->verify($token, self::admitted('rsa', $allowed), $allowed));
    }

    /**
     * A header the library reads differently from the package's reading is
     * refused, though its signature is valid: the package keeps the digits of a
     * number too large for an integer, the library reads a float. The same
     * signature path over a plain header verifies.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testAHeaderTheLibraryReadsDifferentlyNeverVerifies(): void
    {
        $allowed = AlgorithmAllowList::of(['RS256']);
        $key     = self::admitted('rsa', $allowed);
        $apart   = JwsSigner::sign('{"alg":"RS256","kid":"k","x":99999999999999999999}', ['sub' => 'a'], self::key('rsa'), 'RS256');
        $plain   = JwsSigner::sign('{"alg":"RS256","kid":"k","x":1}', ['sub' => 'a'], self::key('rsa'), 'RS256');

        self::assertTrue(JwsSigner::verify($apart, self::key('rsa')->publicKeyPem));
        self::assertFalse((new JoseAdapter)->verify(self::read($apart), $key, $allowed));
        self::assertTrue((new JoseAdapter)->verify(self::read($plain), $key, $allowed));
    }

    /**
     * Rows of `[key, algorithm]`: each key the package signs client assertions
     * with, and the algorithm its type pins.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideClientKeys(): iterable
    {
        yield from ['RSA' => ['rsa', 'PS256'], 'P-256' => ['P-256', 'ES256']];
    }

    /**
     * A client assertion is signed by the key's algorithm under its thumbprint
     * and `typ` `JWT`, with `iss` and `sub` the client, `aud` the token
     * endpoint exactly, a fresh `jti` and `exp` a minute after `iat`, and
     * verifies without the library.
     *
     * @param  string  $key
     * @param  string  $algorithm
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideClientKeys')]
    public function testAClientAssertionIsSigned(string $key, string $algorithm): void
    {
        $signer = self::key($key);
        $now    = CarbonImmutable::createFromTimestampUTC(1900000000);

        $first  = (new JoseAdapter)->signClientAssertion('client-1', 'https://op.example.test/token?x=1', new Secret($signer->privateKeyPem), $now)->reveal();
        $second = (new JoseAdapter)->signClientAssertion('client-1', 'https://op.example.test/token?x=1', new Secret($signer->privateKeyPem), $now)->reveal();

        [$header, $payload] = array_map(static fn (string $part): mixed => json_decode(JwsSigner::decode($part), true), array_slice(explode('.', $first), 0, 2));

        self::assertTrue(JwsSigner::verify($first, $signer->publicKeyPem));
        self::assertSame(['alg' => $algorithm, 'kid' => ClientKey::publicJwk($signer->publicKeyPem)['kid'], 'typ' => 'JWT'], $header);
        self::assertIsArray($payload);
        self::assertSame(['iss', 'sub', 'aud', 'jti', 'iat', 'exp'], array_keys($payload));
        self::assertSame(
            ['iss' => 'client-1', 'sub' => 'client-1', 'aud' => 'https://op.example.test/token?x=1', 'iat' => 1900000000, 'exp' => 1900000060],
            array_diff_key($payload, ['jti' => true]),
        );
        self::assertIsString($payload['jti']);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/D', $payload['jti']);
        self::assertNotSame($payload['jti'], json_decode(JwsSigner::decode(explode('.', $second)[1]), true)['jti'] ?? null);
        self::assertSame([60, 32], [JoseAdapter::ASSERTION_LIFETIME_SECONDS, JoseAdapter::JTI_BYTES]);
    }

    /**
     * Rows of `[key, pinned, header]`: an algorithm a key can be pinned to.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function providePinnedAlgorithms(): iterable
    {
        yield from [
            'RSA, PS256'  => ['rsa', 'PS256', 'PS256'],
            'RSA, RS256'  => ['rsa', 'RS256', 'RS256'],
            'P-256 ES256' => ['P-256', 'ES256', 'ES256'],
        ];
    }

    /**
     * The assertion is signed under the pinned algorithm, its header and the
     * published JWK agreeing, and the `kid` does not depend on the algorithm.
     *
     * @param  string  $key
     * @param  string  $pinned
     * @param  string  $header
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('providePinnedAlgorithms')]
    public function testAClientAssertionIsSignedUnderThePinnedAlgorithm(string $key, string $pinned, string $header): void
    {
        $signer    = self::key($key);
        $now       = CarbonImmutable::createFromTimestampUTC(1900000000);
        $assertion = (new JoseAdapter)->signClientAssertion('client-1', 'https://op.example.test/token', new Secret($signer->privateKeyPem), $now, $pinned)->reveal();
        $read      = json_decode(JwsSigner::decode(explode('.', $assertion)[0]), true);

        self::assertTrue(JwsSigner::verify($assertion, $signer->publicKeyPem));
        self::assertIsArray($read);
        self::assertSame($header, $read['alg']);
        self::assertSame($header, ClientKey::publicJwk($signer->publicKeyPem, $pinned)['alg']);
        self::assertSame(ClientKey::publicJwk($signer->publicKeyPem)['kid'], $read['kid']);
        self::assertSame(ClientKey::publicJwk($signer->publicKeyPem)['kid'], ClientKey::publicJwk($signer->publicKeyPem, $pinned)['kid']);
    }

    /**
     * Rows of `[key, pinned]`: an algorithm the key cannot sign under.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideIncompatibleAlgorithms(): iterable
    {
        yield from [
            'RSA, ES256'     => ['rsa', 'ES256'],
            'RSA, RS384'     => ['rsa', 'RS384'],
            'RSA, none'      => ['rsa', 'none'],
            'RSA, of a case' => ['rsa', 'rs256'],
            'P-256, PS256'   => ['P-256', 'PS256'],
            'P-256, RS256'   => ['P-256', 'RS256'],
            'P-256, ES384'   => ['P-256', 'ES384'],
        ];
    }

    /**
     * A pinned algorithm the key cannot sign under is refused, whether it signs
     * or publishes, and never falls back to the key's default.
     *
     * @param  string  $key
     * @param  string  $pinned
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideIncompatibleAlgorithms')]
    public function testAnIncompatibleAlgorithmIsRefused(string $key, string $pinned): void
    {
        $signer  = self::key($key);
        $refused = 'A client assertion algorithm must fit its key: PS256 or RS256 for an RSA key, ES256 for a P-256 key.';

        try {
            ClientKey::publicJwk($signer->publicKeyPem, $pinned);
            self::fail('A key was published under an algorithm it cannot sign with.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($refused, $exception->getMessage());
        }

        $this->expectExceptionObject(new \InvalidArgumentException($refused));

        (new JoseAdapter)->signClientAssertion('client-1', 'https://op.example.test/token', new Secret($signer->privateKeyPem), CarbonImmutable::now(), $pinned);
    }

    /**
     * A client assertion needs its client and its token endpoint.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClientAssertionNamesItsClientAndAudience(): void
    {
        foreach ([['', 'https://op.example.test/token'], ['client-1', '']] as [$client, $audience]) {
            try {
                (new JoseAdapter)->signClientAssertion($client, $audience, new Secret(self::key('rsa')->privateKeyPem), CarbonImmutable::now());
                self::fail('An assertion without its client or audience was signed.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A client assertion names its client and its token endpoint.', $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[pem]`: keys the package never signs client assertions with.
     *
     * @return iterable<string, array{0: \Closure(): string}>
     */
    public static function provideUnsupportedKeys(): iterable
    {
        yield from [
            'a 1024-bit RSA key' => [static fn (): string => self::key('1024')->privateKeyPem],
            'a P-384 key'        => [static fn (): string => self::key('P-384')->privateKeyPem],
            'not a key'          => [static fn (): string => 'not a key'],
        ];
    }

    /**
     * A key that is neither RSA of at least 2048 bits nor P-256 is a
     * misconfiguration, for signing and for publishing alike.
     *
     * @param  \Closure(): string  $pem
     * @return void
     */
    #[DataProvider('provideUnsupportedKeys')]
    public function testAnUnsupportedKeyIsRefused(\Closure $pem): void
    {
        try {
            ClientKey::fromPrivateKey(new Secret($pem()));
            self::fail('An unsupported key was read.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A client assertion key is an RSA key of at least 2048 bits or an elliptic curve key on P-256.', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);

        ClientKey::publicJwk('not a key');
    }

    /**
     * Rows of `[method, parameter]`: where OpenSSL's description of a private
     * key passes through `ClientKey`.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideSensitiveParameters(): iterable
    {
        yield from [
            'publicOf'  => ['publicOf', 'details'],
            'privateOf' => ['privateOf', 'details'],
            'rsaPublic' => ['rsaPublic', 'rsa'],
            'ecPublic'  => ['ecPublic', 'ec'],
        ];
    }

    /**
     * Each parameter that holds a private key's members is marked, so a trace
     * never shows it.
     *
     * @param  string  $method
     * @param  string  $parameter
     * @return void
     */
    #[DataProvider('provideSensitiveParameters')]
    public function testAPrivateKeysMembersAreMarkedSensitive(string $method, string $parameter): void
    {
        $reflected = new \ReflectionParameter([ClientKey::class, $method], $parameter);

        self::assertCount(1, $reflected->getAttributes(\SensitiveParameter::class));
    }

    /**
     * An unsupported private key's refusal, with arguments kept in traces,
     * shows no private member in any frame.
     *
     * @return void
     */
    public function testARefusedKeysTraceShowsNoPrivateMember(): void
    {
        $previous = ini_set('zend.exception_ignore_args', '0');

        try {
            ClientKey::fromPrivateKey(new Secret(self::key('P-384')->privateKeyPem));
            self::fail('An unsupported key was read.');
        } catch (\InvalidArgumentException $exception) {
            $frame = $exception->getTrace()[0];

            self::assertSame('publicOf', $frame['function']);
            self::assertInstanceOf(\SensitiveParameterValue::class, $frame['args'][0] ?? null);
        } finally {
            ini_set('zend.exception_ignore_args', (string) $previous);
        }
    }

    /**
     * What the library throws while it signs is answered with a fixed message
     * and nothing of the library's: no previous exception and no frame holding
     * the private JWK. A key with no private half makes the library throw.
     *
     * @return void
     */
    public function testALibraryFailureWhileSigningCarriesNothingOfTheLibrary(): void
    {
        $class  = new \ReflectionClass(ClientKey::class);
        $public = $class->newInstanceWithoutConstructor();

        $class->getConstructor()?->invoke($public, 'PS256', ClientKey::publicJwk(self::key('rsa')->publicKeyPem));

        $previous = ini_set('zend.exception_ignore_args', '0');

        try {
            (new \ReflectionMethod(JoseAdapter::class, 'signed'))->invoke(null, $public, '{"sub":"a"}');
            self::fail('A key with no private half signed.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('The client assertion could not be signed.', $exception->getMessage());
            self::assertNull($exception->getPrevious());
            self::assertSame(['signed', 'invoke'], array_slice(array_column($exception->getTrace(), 'function'), 0, 2));
        } finally {
            ini_set('zend.exception_ignore_args', (string) $previous);
        }
    }

    /**
     * A key's public JWK carries its `kid` (its RFC 7638 thumbprint), `use`
     * `sig` and the algorithm it signs with, and nothing private; a dump shows
     * no private member and the key refuses to be serialised.
     *
     * @return void
     */
    public function testAClientKeyPublishesItsPublicHalfOnly(): void
    {
        $rsa = ClientKey::fromPrivateKey(new Secret(self::key('rsa')->privateKeyPem));
        $ec  = ClientKey::fromPrivateKey(new Secret(self::key('P-256')->privateKeyPem));

        self::assertSame(['e', 'kty', 'n', 'kid', 'use', 'alg'], array_keys($rsa->publicJwk));
        self::assertSame(['crv', 'kty', 'x', 'y', 'kid', 'use', 'alg'], array_keys($ec->publicJwk));
        self::assertSame(['RSA', 'sig', 'PS256'], [$rsa->publicJwk['kty'], $rsa->publicJwk['use'], $rsa->algorithm]);
        self::assertSame(['P-256', 'EC', 'sig', 'ES256'], [$ec->publicJwk['crv'], $ec->publicJwk['kty'], $ec->publicJwk['use'], $ec->algorithm]);
        self::assertSame($rsa->publicJwk, ClientKey::publicJwk(self::key('rsa')->publicKeyPem));
        self::assertSame($ec->publicJwk, ClientKey::publicJwk(self::key('P-256')->publicKeyPem));
        self::assertSame($rsa->publicJwk['kid'], $rsa->keyId());
        self::assertSame(ProviderKey::admit(self::key('rsa')->jwk(), AlgorithmAllowList::of(['PS256']))?->thumbprint(), $rsa->keyId());
        self::assertSame(['alg', 'd', 'dp', 'dq', 'e', 'kid', 'kty', 'n', 'p', 'q', 'qi', 'use'], array_keys(self::sorted($rsa->privateJwk())));
        self::assertSame(['alg', 'crv', 'd', 'kid', 'kty', 'use', 'x', 'y'], array_keys(self::sorted($ec->privateJwk())));
        self::assertSame(['algorithm' => 'PS256', 'public_jwk' => $rsa->publicJwk, 'private_jwk' => '[redacted]'], $rsa->__debugInfo());
        self::assertStringNotContainsString($rsa->privateJwk()['d'], print_r($rsa, true));

        $this->expectExceptionObject(new \LogicException('A client assertion key cannot be serialised.'));

        serialize($rsa);
    }

    /**
     * A client key refuses to be unserialised.
     *
     * @return void
     */
    public function testAClientKeyIsNeverUnserialized(): void
    {
        $this->expectExceptionObject(new \LogicException('A client assertion key cannot be unserialised.'));

        unserialize('O:' . strlen(ClientKey::class) . ':"' . ClientKey::class . '":0:{}');
    }

    /**
     * A coordinate OpenSSL reads without its leading zero is published at its
     * full 32 bytes.
     *
     * @return void
     */
    public function testAShortCoordinateIsPublishedPadded(): void
    {
        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAG3T2rkRswc/RWdAI7fk/CKVC4Oo\n"
            . "RiQDc052SQT7oXKfYxCkiLmtzVwnn9N9WgAVwxQCssD90OXqWu61xrR8Gg==\n"
            . "-----END PUBLIC KEY-----\n";

        $jwk = ClientKey::publicJwk($pem);

        self::assertSame('AG3T2rkRswc_RWdAI7fk_CKVC4OoRiQDc052SQT7oXI', $jwk['x'] ?? null);
        self::assertSame('n2MQpIi5rc1cJ5_TfVoAFcMUArLA_dDl6lrutca0fBo', $jwk['y'] ?? null);
    }

    /**
     * The members, sorted by name.
     *
     * @param  array<string, string>  $members
     * @return array<string, string>
     */
    private static function sorted(array $members): array
    {
        ksort($members);

        return $members;
    }

    /**
     * The token, read.
     *
     * @param  string  $compact
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken
     *
     * @throws \LogicException
     */
    private static function read(string $compact): CompactToken
    {
        return CompactToken::parse($compact, 16384) ?? throw new \LogicException('The token was refused.');
    }

    /**
     * The key of the kind, admitted for the allow-list, with no `alg`.
     *
     * @param  string  $kind
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey
     *
     * @throws \LogicException
     */
    private static function admitted(string $kind, AlgorithmAllowList $allowed): ProviderKey
    {
        return ProviderKey::admit(self::key($kind)->jwk(), $allowed) ?? throw new \LogicException('The key was refused.');
    }

    /**
     * A key of the kind, generated once: `rsa`, `attacker`, `1024`, or a curve.
     *
     * @param  string  $kind
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(string $kind): FakeSigningKey
    {
        return self::$keys[$kind] ??= match ($kind) {
            'rsa', 'attacker' => FakeSigningKey::rsa('k'),
            '1024'            => FakeSigningKey::rsa('k', 1024),
            default           => FakeSigningKey::ec('k', $kind),
        };
    }
}
