<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Oidc;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\JoseAdapter;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\JwsSigner;
use SineMacula\Laravel\Sso\Testing\Oidc\PssSignature;
use Tests\Concerns\TreatsWarningsAsErrors;

/**
 * Unit tests for the fake provider's ID tokens and their hand-made signatures
 * (SSO-12.4): every knob answers a new token and leaves the old one alone, and
 * each algorithm's signature is made and checked with OpenSSL alone, PSS built
 * by hand.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeIdToken::class)]
#[CoversClass(JwsSigner::class)]
#[CoversClass(PssSignature::class)]
#[CoversClass(FakeSigningKey::class)]
final class FakeIdTokenTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /** @var array<string, \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey> The keys, generated once. */
    private static array $keys = [];

    /**
     * Claims and header members are set and removed on a new token, and the
     * token is signed with its header.
     *
     * @return void
     */
    public function testKnobsAnswerANewToken(): void
    {
        $token   = new FakeIdToken(self::key('rsa'), ['alg' => 'RS256', 'kid' => 'k1'], ['sub' => 'a', 'aud' => 'c']);
        $changed = $token->with('sub', 7)->without('aud')->withHeader('crit', ['x'])->withoutHeader('kid')->with('aud', ['c', 'd']);

        self::assertSame(['sub' => 'a', 'aud' => 'c'], $token->claims());
        self::assertSame(['alg' => 'RS256', 'kid' => 'k1'], $token->header());
        self::assertSame(['sub' => 7, 'aud' => ['c', 'd']], $changed->claims());
        self::assertSame(['alg' => 'RS256', 'crit' => ['x']], $changed->header());
        self::assertSame($changed->toString(), (string) $changed);
        self::assertSame(['alg' => 'RS256', 'crit' => ['x']], json_decode(JwsSigner::decode(explode('.', (string) $changed)[0]), true));
        self::assertTrue(JwsSigner::verify((string) $changed, self::key('rsa')->publicKeyPem));
    }

    /**
     * A token signed with another key names its `kid`, or none.
     *
     * @return void
     */
    public function testSignedWithAnotherKeyNamesItsKid(): void
    {
        $token = new FakeIdToken(self::key('rsa'), ['alg' => 'RS256', 'kid' => 'k1', 'typ' => 'JWT'], ['sub' => 'a']);

        self::assertSame(['alg' => 'ES256', 'kid' => 'e1', 'typ' => 'JWT'], $token->signedWith(self::key('ec'), 'ES256')->header());
        self::assertSame(['alg' => 'PS256', 'typ' => 'JWT'], $token->signedWith(self::key('rsa')->withKid(null), 'PS256')->header());
        self::assertTrue(JwsSigner::verify((string) $token->signedWith(self::key('ec'), 'ES256'), self::key('ec')->publicKeyPem));
    }

    /**
     * `at_hash` is the left half of the access token's hash for the token's
     * algorithm, encoded.
     *
     * @return void
     */
    public function testTheAccessTokenHashFollowsTheAlgorithm(): void
    {
        $token = new FakeIdToken(self::key('rsa'), ['alg' => 'RS256'], []);

        self::assertSame(JwsSigner::encode(substr(hash('sha256', 'at', true), 0, 16)), $token->accessTokenHash('at')->claims()['at_hash']);
        self::assertSame(JwsSigner::encode(substr(hash('sha384', 'at', true), 0, 24)), $token->withHeader('alg', 'PS384')->accessTokenHash('at')->claims()['at_hash']);
        self::assertSame(JwsSigner::encode(substr(hash('sha512', 'at', true), 0, 32)), $token->withHeader('alg', 'ES512')->accessTokenHash('at')->claims()['at_hash']);
        self::assertSame('77QmUPtjPfzWtF2AnpK9RQ', $token->accessTokenHash('jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y')->claims()['at_hash']);
    }

    /**
     * The hostile forms: raw JSON whole, an empty signature, an HMAC, five
     * segments and another token's signature.
     *
     * @return void
     */
    public function testTheHostileFormsAreBuilt(): void
    {
        $token = new FakeIdToken(self::key('rsa'), ['alg' => 'HS256', 'kid' => 'k1'], ['sub' => 'a']);

        $raw = (string) $token->withHeader('alg', 'RS256')->withHeaderJson('{"alg":"RS256","alg":"none"}')->withPayloadJson('{"sub":"a","sub":"b"}');

        self::assertSame(['{"alg":"RS256","alg":"none"}', '{"sub":"a","sub":"b"}'], array_map(JwsSigner::decode(...), array_slice(explode('.', $raw), 0, 2)));
        self::assertStringEndsWith('.', (string) $token->unsigned());
        self::assertCount(3, explode('.', (string) $token->unsigned()));

        $input = static fn (FakeIdToken $unsigned): string => substr((string) $unsigned->unsigned(), 0, -1);
        $hs512 = $token->withHeader('alg', 'HS512');

        self::assertSame(JwsSigner::encode(hash_hmac('sha256', $input($token), 'secret', true)), explode('.', (string) $token->hmac('secret'))[2]);
        self::assertSame(JwsSigner::encode(hash_hmac('sha512', $input($hs512), 'secret', true)), explode('.', (string) $hs512->hmac('secret'))[2]);
        self::assertCount(5, explode('.', (string) $token->asJwe()));
        self::assertSame('c2ln', explode('.', (string) $token->withHeader('alg', 'RS256')->withSignatureOf('a.b.c2ln'))[2]);
        self::assertSame('', explode('.', (string) $token->withHeader('alg', 'RS256')->withSignatureOf('a.b'))[2]);
    }

    /**
     * Rows of `[algorithm, key]`: every algorithm the fake signs, with a key.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideAlgorithms(): iterable
    {
        foreach (['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'] as $algorithm) {
            yield $algorithm => [$algorithm, 'rsa'];
        }

        yield from ['ES256' => ['ES256', 'ec'], 'ES384' => ['ES384', 'P-384'], 'ES512' => ['ES512', 'P-521'], 'PS256 on 3072 bits' => ['PS256', 'rsa-3072']];
    }

    /**
     * Each algorithm signs and verifies with OpenSSL alone, and a changed
     * signature, payload or key does not verify.
     *
     * @param  string  $algorithm
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideAlgorithms')]
    public function testEachAlgorithmSignsAndVerifies(string $algorithm, string $key): void
    {
        $token = JwsSigner::sign(['alg' => $algorithm], ['sub' => 'a'], self::key($key));

        [$header, , $signature] = explode('.', $token);

        self::assertTrue(JwsSigner::verify($token, self::key($key)->publicKeyPem));
        self::assertFalse(JwsSigner::verify($header . '.' . JwsSigner::encode('{"sub":"b"}') . '.' . $signature, self::key($key)->publicKeyPem));
        self::assertFalse(JwsSigner::verify($token, self::key(str_starts_with($key, 'rsa') ? 'other' : 'ec-other')->publicKeyPem));
    }

    /**
     * A token of an algorithm the fake does not sign is refused, and one whose
     * header names none never verifies.
     *
     * @return void
     */
    public function testAnUnknownAlgorithmIsRefused(): void
    {
        self::assertFalse(JwsSigner::verify('a.b', self::key('rsa')->publicKeyPem));
        self::assertFalse(JwsSigner::verify(JwsSigner::hmac(['alg' => 'HS256'], [], 'x'), self::key('rsa')->publicKeyPem));
        self::assertFalse(JwsSigner::verify(JwsSigner::unsigned(['alg' => 'none'], []), self::key('rsa')->publicKeyPem));
        self::assertFalse(PssSignature::verify('m', 'not a signature', 'not a key', 'sha256'));

        $this->expectExceptionObject(new \LogicException('The fake provider cannot sign [HS256].'));

        JwsSigner::sign(['alg' => 'HS256'], [], self::key('rsa'));
    }

    /**
     * A key describes itself: its type, curve, size and JWKs, public and
     * private.
     *
     * @return void
     */
    public function testAKeyDescribesItself(): void
    {
        $rsa   = self::key('rsa');
        $ec    = self::key('P-384');
        $ecJwk = $ec->jwk();

        self::assertIsString($ecJwk['x']);
        self::assertSame(['RSA', null, 2048, 'k1'], [$rsa->type, $rsa->curve, $rsa->bits, $rsa->kid]);
        self::assertSame(['EC', 'P-384', 384], [$ec->type, $ec->curve, $ec->bits]);
        self::assertSame(['kty', 'n', 'e', 'kid', 'use'], array_keys($rsa->jwk()));
        self::assertSame(['kty', 'n', 'e', 'kid', 'alg', 'x5t'], array_keys($rsa->jwk('RS256', null, ['x5t' => 'a'])));
        self::assertSame(['kty', 'crv', 'x', 'y', 'kid', 'use', 'alg'], array_keys($ec->jwk('ES384')));
        self::assertSame(64, strlen($ecJwk['x']));
        self::assertSame(['kty', 'n', 'e', 'kid', 'use', 'd', 'p', 'q', 'dp', 'dq', 'qi'], array_keys($rsa->privateJwk()));
        self::assertSame(['kty', 'crv', 'x', 'y', 'kid', 'use', 'd'], array_keys($ec->privateJwk()));
        self::assertSame(['kty', 'n', 'e', 'use'], array_keys($rsa->withKid(null)->jwk()));

        $this->expectExceptionObject(new \LogicException('The fake OpenID provider could not read its key.'));

        new FakeSigningKey('not a key', 'k');
    }

    /**
     * Every change answers a new token and leaves the one it was asked of as it
     * was, its text included.
     *
     * @return void
     */
    public function testEveryChangeLeavesTheTokenAsItWas(): void
    {
        $token = new FakeIdToken(self::key('rsa'), ['alg' => 'RS256', 'kid' => 'k1'], ['sub' => 'a', 'aud' => 'c']);
        $text  = (string) $token;

        $token->with('sub', 'b');
        $token->without('aud');
        $token->withHeader('crit', ['x']);
        $token->withoutHeader('kid');
        $token->signedWith(self::key('other'), 'PS256');
        $token->withHeaderJson('{}');
        $token->withPayloadJson('{}');
        $token->unsigned();
        $token->hmac('secret');
        $token->asJwe();
        $token->withSignatureOf('a.b.c');

        self::assertSame(['sub' => 'a', 'aud' => 'c'], $token->claims());
        self::assertSame(['alg' => 'RS256', 'kid' => 'k1'], $token->header());
        self::assertSame($text, (string) $token);
    }

    /**
     * A JWE is exactly the unsigned form with its three other members after it,
     * and a signature taken from another keeps the token's own header and
     * payload.
     *
     * @return void
     */
    public function testTheFormsAreExact(): void
    {
        $token    = new FakeIdToken(self::key('rsa'), ['alg' => 'RS256'], ['sub' => 'a']);
        $unsigned = (string) $token->unsigned();

        self::assertSame($unsigned . 'AAAA.AAAA.AAAA', (string) $token->asJwe());
        self::assertSame($unsigned . 'c2ln', (string) $token->withSignatureOf('a.b.c2ln'));
        self::assertSame($unsigned, (string) $token->withSignatureOf('a.b'));
    }

    /**
     * Rows of `[bits]`: a modulus whose encoded message starts in each place.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideModulusSizes(): iterable
    {
        yield from ['a whole byte' => [2048], 'one bit over' => [2049], 'two bits over' => [2050]];
    }

    /**
     * A PSS signature of any modulus size, including one that is no whole
     * number of bytes, verifies, and a changed message does not.
     *
     * @param  int  $bits
     * @return void
     */
    #[DataProvider('provideModulusSizes')]
    public function testAPssSignatureOfAnyModulusVerifies(int $bits): void
    {
        $key    = FakeSigningKey::rsa('p1', $bits);
        $signed = explode('.', JwsSigner::sign(['alg' => 'PS256', 'kid' => 'p1'], ['sub' => 'a'], $key));

        self::assertTrue(PssSignature::verify($signed[0] . '.' . $signed[1], JwsSigner::decode($signed[2]), $key->publicKeyPem, 'sha256'));
        self::assertFalse(PssSignature::verify($signed[0] . '.' . $signed[1] . 'x', JwsSigner::decode($signed[2]), $key->publicKeyPem, 'sha256'));
    }

    /**
     * A PSS signature is one the library accepts.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testAPssSignatureIsOneTheLibraryAccepts(): void
    {
        $key     = self::key('rsa');
        $allowed = AlgorithmAllowList::of(['PS256']);
        $admit   = ProviderKey::admit($key->jwk(), $allowed)                                                            ?? throw new \LogicException('The key was refused.');
        $read    = CompactToken::parse(JwsSigner::sign(['alg' => 'PS256', 'kid' => 'k1'], ['sub' => 'a'], $key), 16384) ?? throw new \LogicException('The token was refused.');

        self::assertTrue((new JoseAdapter)->verify($read, $admit, $allowed));
    }

    /**
     * A signature OpenSSL made under PSS with a salt of the hash's length is
     * accepted, and refused once its message or signature changes or it is
     * judged under another key.
     *
     * @return void
     */
    public function testAPssSignatureOpensslMadeIsAccepted(): void
    {
        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5vOzqxa8/3UH43JBfzR4\n"
            . "VOBc4et8W66Tsg82Tlkslx/FP1gSuqA83rwA6P3izGDwbiHzAibJoDMuCX3KwEvZ\n"
            . "Lz4LsOAK1RTl9x7PKhy7fBqRS94NH8cadxykdnsWCRgt8e7/EdThjf/eqzGnB4JN\n"
            . "a+ZOOY6/amEs5td2elxhkSNF/tx/BvJE6Y3+wl4j9i+XGcUIBwzdYi1la29YESWG\n"
            . "g4Bm3/3NnK9SLk9i8nSlPrG9andPvaMA/WXXm1CW9az3N0KPLnUcMNFXTY/MSVn3\n"
            . "2OCL6d19KztsQ0Ou8NnYlj2ulRoWxklN9a3UvDOSeG1DKCDYyr6yJztM0AoFKEjT\n"
            . "DQIDAQAB\n"
            . "-----END PUBLIC KEY-----\n";
        $message   = 'eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJwZXJzb24ifQ';
        $signature = JwsSigner::decode(
            'swFFT877f00jjvuaZnMl1wK37mZ0zRd9jwJoBiFg_Hfbzrypu5pjHzAWNXRNPrBIXN6l7Ir-6tVmE1cNBES29hIW4TX0RQcnvbXAcn8G1pibIwdqo10UIDgP'
            . 'bHtRqaamzNA_s37rD3SArMfqagOHZoOYvbkRD48wfJOUJveVcziL7DjUDeRxX_rHI33zrBRoj5GfBF23k7kSPehCKX9SQgoYQ0RwH4vzH9axtbc1dsETCnr2'
            . 'iJV3YElK9Bl-qDWn0WPuvkYB4Rez_zr3RdcVe5sknv3tpUGmGaFx8hVbAxVxXh0hIYtZ0jWbNVpiftuFsnQ7ARrCf12WhFHCmWpTxA',
        );

        self::assertTrue(PssSignature::verify($message, $signature, $pem, 'sha256'));
        self::assertTrue(JwsSigner::verify($message . '.' . JwsSigner::encode($signature), $pem));
        self::assertFalse(PssSignature::verify($message . 'x', $signature, $pem, 'sha256'));
        self::assertFalse(PssSignature::verify($message, strrev($signature), $pem, 'sha256'));
        self::assertFalse(PssSignature::verify($message, $signature, self::key('rsa')->publicKeyPem, 'sha256'));
        self::assertFalse(PssSignature::verify($message, $signature, 'not a key', 'sha256'));
    }

    /**
     * Rows of `[change]`: what breaks an otherwise valid encoded message.
     *
     * @return iterable<string, array{0: \Closure(string): string}>
     */
    public static function provideBrokenEncodings(): iterable
    {
        yield from [
            'another trailer' => [static fn (string $encoded): string => substr($encoded, 0, -1) . "\xbd"],
            'no trailer'      => [static fn (string $encoded): string => "\x00" . substr($encoded, 0, -1)],
        ];
    }

    /**
     * An encoded message whose trailer is broken is not an encoding of
     * anything, though its digest may fit.
     *
     * @param  \Closure(string): string  $change
     * @return void
     */
    #[DataProvider('provideBrokenEncodings')]
    public function testAPssSignatureNeedsItsTrailer(\Closure $change): void
    {
        $key    = self::key('rsa');
        $signed = explode('.', JwsSigner::sign(['alg' => 'PS256'], ['sub' => 'a'], $key));

        openssl_public_decrypt(JwsSigner::decode($signed[2]), $encoded, $key->publicKeyPem, OPENSSL_NO_PADDING);
        openssl_private_encrypt($change((string) $encoded), $broken, $key->privateKeyPem, OPENSSL_NO_PADDING);

        self::assertFalse(PssSignature::verify($signed[0] . '.' . $signed[1], (string) $broken, $key->publicKeyPem, 'sha256'));
    }

    /**
     * A signature with a coordinate of the wrong form never verifies, and
     * nothing is read from what is not a token.
     *
     * @return void
     */
    public function testWhatIsNotASignedTokenNeverVerifies(): void
    {
        $key  = self::key('ec');
        $body = JwsSigner::encode('{"alg":"ES256"}') . '.' . JwsSigner::encode('{}');

        self::assertFalse(JwsSigner::verify($body . '.', $key->publicKeyPem));
        self::assertFalse(JwsSigner::verify(JwsSigner::encode('"text"') . '.e30.AA', $key->publicKeyPem));
        self::assertFalse(JwsSigner::verify(JwsSigner::encode('{"alg":1}') . '.e30.AA', $key->publicKeyPem));
        self::assertFalse(JwsSigner::verify('only.two', $key->publicKeyPem));
    }

    /**
     * Rows of `[first byte]`: where a signature's first integer starts, in the
     * forms DER writes differently.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideFirstBytes(): iterable
    {
        yield from ['a leading zero' => [0x00], 'under the top bit' => [0x7F], 'at the top bit' => [0x80]];
    }

    /**
     * An ECDSA signature verifies whatever its first integer starts with.
     *
     * @param  int  $first
     * @return void
     */
    #[DataProvider('provideFirstBytes')]
    public function testAnEcdsaSignatureVerifiesWhateverItStartsWith(int $first): void
    {
        $key = self::key('ec');

        for ($attempt = 0; $attempt < 20000; $attempt++) {

            $signed = JwsSigner::sign(['alg' => 'ES256'], ['attempt' => $attempt], $key);

            if (ord(JwsSigner::decode(explode('.', $signed)[2])[0]) === $first) {
                self::assertTrue(JwsSigner::verify($signed, $key->publicKeyPem));

                return;
            }
        }

        self::fail('No signature started as asked.');
    }

    /**
     * A key's default size, type and curve; each coordinate of an elliptic
     * curve key exactly OpenSSL's, its private member too, and an RSA key's
     * members with no padding.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testAKeysMembersAreExact(): void
    {
        $ec      = self::key('P-384');
        $details = (array) openssl_pkey_get_details((openssl_pkey_get_private($ec->privateKeyPem) ?: null) ?? throw new \LogicException('No key.'));
        $point   = (array) $details['ec'];
        $wide    = static fn (string $name): string => str_pad((string) $point[$name], 48, "\x00", STR_PAD_LEFT);
        $public  = $ec->jwk();
        $private = $ec->privateJwk();

        self::assertIsString($public['x']);
        self::assertIsString($public['y']);
        self::assertIsString($private['d']);
        self::assertSame([$wide('x'), $wide('y')], [JwsSigner::decode($public['x']), JwsSigner::decode($public['y'])]);
        self::assertSame($wide('d'), JwsSigner::decode($private['d']));

        $rsa    = self::key('rsa');
        $rsaJwk = $rsa->jwk();

        self::assertIsString($rsaJwk['n']);

        self::assertSame(2048, FakeSigningKey::rsa()->bits);
        self::assertSame('rsa-1', FakeSigningKey::rsa()->kid);
        self::assertSame(['EC', 'P-256', 'ec-1'], [FakeSigningKey::ec()->type, FakeSigningKey::ec()->curve, FakeSigningKey::ec()->kid]);
        self::assertSame(256, strlen(JwsSigner::decode($rsaJwk['n'])));
        self::assertStringNotContainsString('=', $rsaJwk['n']);
        self::assertSame('AQAB', $rsaJwk['e']);
    }

    /**
     * Rows of `[separator, accepted]`: the byte between an encoding's padding
     * and its salt.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideSeparators(): iterable
    {
        yield from ['the separator' => ["\x01", true], 'another byte' => ["\x02", false]];
    }

    /**
     * An encoding whose digest fits but whose padding does not separate its
     * salt with `0x01` is not an encoding of anything; the same encoding with
     * that byte is.
     *
     * @param  string  $separator
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideSeparators')]
    public function testAPssSignatureNeedsItsPadding(string $separator, bool $accepted): void
    {
        $key     = self::key('rsa');
        $salt    = str_repeat("\x05", 32);
        $message = 'message';
        $digest  = hash('sha256', str_repeat("\x00", 8) . hash('sha256', $message, true) . $salt, true);
        $block   = str_repeat("\x00", 256 - 32 - 32 - 2) . $separator . $salt;
        $mask    = '';

        for ($counter = 0; strlen($mask) < strlen($block); $counter++) {
            $mask .= hash('sha256', $digest . pack('N', $counter), true);
        }

        $masked    = $block ^ substr($mask, 0, strlen($block));
        $masked[0] = chr(ord($masked[0]) & 0x7F);

        openssl_private_encrypt($masked . $digest . "\xbc", $signature, $key->privateKeyPem, OPENSSL_NO_PADDING);

        self::assertSame($accepted, PssSignature::verify($message, (string) $signature, $key->publicKeyPem, 'sha256'));
    }

    /**
     * A key by its name, generated once.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(string $name): FakeSigningKey
    {
        return self::$keys[$name] ??= match ($name) {
            'rsa'      => FakeSigningKey::rsa('k1'),
            'other'    => FakeSigningKey::rsa('k2'),
            'rsa-3072' => FakeSigningKey::rsa('k3', 3072),
            'ec'       => FakeSigningKey::ec('e1'),
            'ec-other' => FakeSigningKey::ec('e2'),
            default    => FakeSigningKey::ec('e3', $name),
        };
    }
}
