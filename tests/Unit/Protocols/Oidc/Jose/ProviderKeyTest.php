<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc\Jose;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Base64Url;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\PublicKeyEncoding;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use Tests\Concerns\TreatsWarningsAsErrors;

/**
 * Unit tests for admitting an identity provider's public key (SSO-7.3): public
 * RSA keys of at least 2048 bits and elliptic curve keys on the three curves,
 * `use` `sig`, `key_ops` with `verify` and an allowed `alg` that fits; and the
 * check at use, the stored form and the RFC 7638 thumbprint.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProviderKey::class)]
#[CoversClass(PublicKeyEncoding::class)]
final class ProviderKeyTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /** @var array<string, \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey> The keys, generated once. */
    private static array $keys = [];

    /**
     * An RSA key is admitted with its size, its PEM and its stored form, in a
     * fixed order and with nothing but its public members.
     *
     * @return void
     */
    public function testAnRsaKeyIsAdmitted(): void
    {
        $key = self::key('rsa');
        $jwk = $key->jwk('RS256', 'sig', ['key_ops' => ['verify'], 'x5t' => 'ignored']);

        $admitted = ProviderKey::admit($jwk, self::all());

        self::assertNotNull($admitted);
        self::assertSame(2048, $admitted->bits);
        self::assertSame('k1', $admitted->keyId());
        self::assertSame('RSA', $admitted->keyType());
        self::assertSame(['kty', 'kid', 'use', 'key_ops', 'alg', 'n', 'e'], array_keys($admitted->toArray()));
        self::assertSame(['kty' => 'RSA', 'kid' => 'k1', 'use' => 'sig', 'key_ops' => ['verify'], 'alg' => 'RS256', 'n' => $jwk['n'], 'e' => $jwk['e']], $admitted->toArray());
        self::assertSame($key->publicKeyPem, $admitted->publicKeyPem);
    }

    /**
     * An elliptic curve key on each curve is admitted, with its size.
     *
     * @return void
     */
    public function testAnEllipticCurveKeyOnEachCurveIsAdmitted(): void
    {
        foreach (['P-256' => [256, 'ES256'], 'P-384' => [384, 'ES384'], 'P-521' => [521, 'ES512']] as $curve => [$bits, $algorithm]) {

            $admitted = ProviderKey::admit(self::key($curve)->jwk($algorithm), self::all());

            self::assertSame($bits, $admitted?->bits, $curve);
            self::assertSame(['kty', 'kid', 'use', 'alg', 'crv', 'x', 'y'], array_keys($admitted->toArray()), $curve);
            self::assertTrue($admitted->fits($algorithm, self::all()), $curve);
        }
    }

    /**
     * A key with no `kid`, `use` or `alg` is admitted, and has no `kid`.
     *
     * @return void
     */
    public function testAKeyWithNoOptionalMembersIsAdmitted(): void
    {
        $admitted = ProviderKey::admit(self::key('rsa')->withKid(null)->jwk(null, null), self::all());

        self::assertNull($admitted?->keyId());
        self::assertSame(['kty', 'n', 'e'], array_keys((array) $admitted?->toArray()));
    }

    /**
     * Rows of `[key, changes, algorithms]`: keys the package does not admit.
     *
     * @return iterable<string, array{0: string, 1: array<string, mixed>, 2?: list<string>}>
     */
    public static function provideInadmissibleKeys(): iterable
    {
        yield from [
            'an oct key'                => ['rsa', ['kty' => 'oct', 'k' => 'c2VjcmV0']],
            'an OKP key'                => ['rsa', ['kty' => 'OKP']],
            'kty in lower case'         => ['rsa', ['kty' => 'rsa']],
            'no kty'                    => ['rsa', ['kty' => null]],
            'a private RSA member'      => ['rsa', ['d' => 'AQAB']],
            'p'                         => ['rsa', ['p' => 'AQAB']],
            'q'                         => ['rsa', ['q' => 'AQAB']],
            'dp'                        => ['rsa', ['dp' => 'AQAB']],
            'dq'                        => ['rsa', ['dq' => 'AQAB']],
            'qi'                        => ['rsa', ['qi' => 'AQAB']],
            'oth'                       => ['rsa', ['oth' => []]],
            'a symmetric k'             => ['rsa', ['k' => 'c2VjcmV0']],
            'a private EC member'       => ['P-256', ['d' => 'AQAB']],
            'use enc'                   => ['rsa', ['use' => 'enc']],
            'use null'                  => ['rsa', ['use' => null]],
            'key_ops without verify'    => ['rsa', ['key_ops' => ['sign']]],
            'key_ops not a list'        => ['rsa', ['key_ops' => ['a' => 'verify']]],
            'key_ops with a number'     => ['rsa', ['key_ops' => ['verify', 1]]],
            'key_ops a string'          => ['rsa', ['key_ops' => 'verify']],
            'kid empty'                 => ['rsa', ['kid' => '']],
            'kid a number'              => ['rsa', ['kid' => 0]],
            'kid null'                  => ['rsa', ['kid' => null]],
            'alg off the allow-list'    => ['rsa', ['alg' => 'PS256'], ['RS256']],
            'alg HS256'                 => ['rsa', ['alg' => 'HS256']],
            'alg not a string'          => ['rsa', ['alg' => 256]],
            'an RSA alg on an EC key'   => ['P-256', ['alg' => 'RS256']],
            'an EC alg on an RSA key'   => ['rsa', ['alg' => 'ES256']],
            'ES512 on a P-256 key'      => ['P-256', ['alg' => 'ES512']],
            'ES256 on a P-384 key'      => ['P-384', ['alg' => 'ES256']],
            'an RSA key with a curve'   => ['rsa', ['crv' => 'P-256']],
            'a padded modulus'          => ['rsa', ['n' => 'AQAB==']],
            'an empty modulus'          => ['rsa', ['n' => '']],
            'a modulus not a string'    => ['rsa', ['n' => 1]],
            'no exponent'               => ['rsa', ['e' => null]],
            'an even exponent'          => ['rsa', ['e' => 'Ag']],
            'an exponent of one'        => ['rsa', ['e' => 'AQ']],
            'an exponent of zero bytes' => ['rsa', ['e' => 'AA']],
            'an exponent of nine bytes' => ['rsa', ['e' => 'AQAAAAAAAAAB']],
            'an unknown curve'          => ['P-256', ['crv' => 'P-192']],
            'a curve not a string'      => ['P-256', ['crv' => 256]],
            'a short coordinate'        => ['P-256', ['x' => 'AQAB']],
            'a point off the curve'     => ['P-256', ['y' => 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA']],
            'no y'                      => ['P-256', ['y' => null]],
        ];
    }

    /**
     * A key that is not a public RSA or elliptic curve signing key the package
     * reads, for the allow-list, is not admitted.
     *
     * @param  string  $key
     * @param  array<string, mixed>  $changes
     * @param  list<string>  $algorithms
     * @return void
     */
    #[DataProvider('provideInadmissibleKeys')]
    public function testAnInadmissibleKeyIsNotAdmitted(string $key, array $changes, array $algorithms = ['RS256', 'PS256', 'ES256', 'ES384', 'ES512']): void
    {
        $kept   = array_filter([...self::key($key)->jwk(), ...$changes], static fn (mixed $value): bool => $value !== null);
        $nulled = array_filter($changes, static fn (mixed $value, string $name): bool => $value === null && in_array($name, ['kid', 'use'], true), ARRAY_FILTER_USE_BOTH);
        $jwk    = [...$kept, ...$nulled];

        self::assertNull(ProviderKey::admit($jwk, AlgorithmAllowList::of($algorithms)));
    }

    /**
     * An RSA key of 2048 bits is admitted and one of 2047 is not; a 1024-bit
     * key never is.
     *
     * @return void
     */
    public function testAnRsaKeyIsAdmittedFromTwoThousandAndFortyEightBits(): void
    {
        $modulus = static fn (int $bits): string => Base64Url::encode("\xff" . str_repeat("\xff", intdiv($bits, 8) - 2) . "\xfb");
        $sized   = static fn (int $bits): array => ['kty' => 'RSA', 'n' => $modulus($bits), 'e' => 'AQAB'];

        self::assertSame(2048, ProviderKey::admit($sized(2048), self::all())?->bits);
        self::assertNull(ProviderKey::admit(['kty' => 'RSA', 'n' => Base64Url::encode("\x7f" . str_repeat("\xff", 254) . "\xfb"), 'e' => 'AQAB'], self::all()));
        self::assertNull(ProviderKey::admit(self::key('1024')->jwk(), self::all()));
        self::assertSame([2048, 16384], [ProviderKey::MIN_RSA_BITS, ProviderKey::MAX_RSA_BITS]);
    }

    /**
     * Rows of `[key, alg, algorithm, fits]`: whether a key fits an algorithm
     * under the allow-list.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: string, 3: bool}>
     */
    public static function provideFits(): iterable
    {
        yield from [
            'RSA, no alg, RS256'   => ['rsa', null, 'RS256', true],
            'RSA, no alg, PS256'   => ['rsa', null, 'PS256', true],
            'RSA, no alg, ES256'   => ['rsa', null, 'ES256', false],
            'RSA, no alg, HS256'   => ['rsa', null, 'HS256', false],
            'RSA, no alg, RS384'   => ['rsa', null, 'RS384', false],
            'RSA, RS256, RS256'    => ['rsa', 'RS256', 'RS256', true],
            'RSA, RS256, PS256'    => ['rsa', 'RS256', 'PS256', false],
            'P-256, no alg, ES256' => ['P-256', null, 'ES256', true],
            'P-256, no alg, ES512' => ['P-256', null, 'ES512', false],
            'P-256, no alg, RS256' => ['P-256', null, 'RS256', false],
            'P-256, ES256, ES256'  => ['P-256', 'ES256', 'ES256', true],
            'P-521, no alg, ES512' => ['P-521', null, 'ES512', true],
        ];
    }

    /**
     * A key fits only an allowed algorithm of its type and curve, and only its
     * own `alg` when it has one.
     *
     * @param  string  $key
     * @param  ?string  $alg
     * @param  string  $algorithm
     * @param  bool  $fits
     * @return void
     */
    #[DataProvider('provideFits')]
    public function testAKeyFitsOnlyItsAlgorithms(string $key, ?string $alg, string $algorithm, bool $fits): void
    {
        $allowed  = AlgorithmAllowList::of(['RS256', 'PS256', 'ES256', 'ES512']);
        $admitted = ProviderKey::admit(self::key($key)->jwk($alg), $allowed);

        self::assertSame($fits, $admitted?->fits($algorithm, $allowed));
    }

    /**
     * The thumbprint is RFC 7638's: the SHA-256 of the required members in
     * lexical order, whatever else the key carries.
     *
     * @return void
     */
    public function testTheThumbprintIsRfc7638s(): void
    {
        // RFC 7638 §3.1's example key and thumbprint
        $jwk = [
            'kty' => 'RSA',
            'n'   => implode('', [
                '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64t',
                'Z_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbO',
                'pbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
            ]),
            'e'   => 'AQAB',
            'alg' => 'RS256',
            'kid' => '2011-04-29',
        ];

        self::assertSame('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', ProviderKey::admit($jwk, self::all())?->thumbprint());

        $ec      = ProviderKey::admit(self::key('P-256')->jwk('ES256'), self::all());
        $members = array_intersect_key((array) $ec?->toArray(), array_flip(['crv', 'kty', 'x', 'y']));

        ksort($members);

        self::assertSame(Base64Url::encode(hash('sha256', (string) json_encode($members), true)), $ec?->thumbprint());
    }

    /**
     * Rows of `[exponent, admitted]`: an RSA exponent, as big-endian bytes.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideExponents(): iterable
    {
        yield from [
            'three'                        => ["\x03", true],
            'the usual one'                => ["\x01\x00\x01", true],
            'with leading zeros'           => ["\x00\x00\x01\x00\x01", true],
            'odd, after an even byte'      => ["\x02\x03", true],
            'at eight bytes'               => ["\x01\x00\x00\x00\x00\x00\x00\x01", true],
            'at eight bytes, zeros before' => ["\x00\x01\x00\x00\x00\x00\x00\x00\x01", true],
            'at nine bytes'                => ["\x01\x00\x00\x00\x00\x00\x00\x00\x01", false],
            'even, after an odd byte'      => ["\x03\x02", false],
            'one'                          => ["\x01", false],
            'one, with leading zeros'      => ["\x00\x01", false],
            'nothing but zeros'            => ["\x00\x00", false],
        ];
    }

    /**
     * An exponent is admitted when, read without its leading zeros, it is odd,
     * at least three and at most eight bytes long.
     *
     * @param  string  $exponent
     * @param  bool  $admitted
     * @return void
     */
    #[DataProvider('provideExponents')]
    public function testAnExponentIsAdmittedOnlyWhenOddAndInRange(string $exponent, bool $admitted): void
    {
        $jwk = ['kty' => 'RSA', 'n' => Base64Url::encode("\xff" . str_repeat("\xff", 254) . "\xfb"), 'e' => Base64Url::encode($exponent)];

        self::assertSame($admitted, ProviderKey::admit($jwk, self::all()) !== null);
    }

    /**
     * An RSA key of the largest size is admitted, and one bit more is not.
     *
     * @return void
     */
    public function testAnRsaKeyIsAdmittedUpToItsLargestSize(): void
    {
        $largest = ['kty' => 'RSA', 'n' => Base64Url::encode(str_repeat("\xff", 2047) . "\xfb"), 'e' => 'AQAB'];
        $over    = ['kty' => 'RSA', 'n' => Base64Url::encode("\x01" . str_repeat("\xff", 2047) . "\xfb"), 'e' => 'AQAB'];

        self::assertSame(16384, ProviderKey::admit($largest, self::all())?->bits);
        self::assertNull(ProviderKey::admit($over, self::all()));
    }

    /**
     * A modulus of nothing but zeros is written as the integer zero, which
     * OpenSSL reads at no size, so it is not admitted.
     *
     * @return void
     */
    public function testAModulusOfNothingIsNotAdmitted(): void
    {
        self::assertSame(0, PublicKeyEncoding::rsa("\x00", "\x01\x00\x01")['bits'] ?? null);
        self::assertNull(ProviderKey::admit(['kty' => 'RSA', 'n' => 'AA', 'e' => 'AQAB'], self::all()));
    }

    /**
     * A modulus's leading zeros are not written, so the same key has the same
     * PEM however its JWK pads it.
     *
     * @return void
     */
    public function testLeadingZerosOfAModulusAreNotWritten(): void
    {
        $key     = self::key('rsa');
        $modulus = Base64Url::decode(is_string($key->jwk()['n']) ? $key->jwk()['n'] : '');
        $padded  = ['kty' => 'RSA', 'n' => Base64Url::encode("\x00\x00" . $modulus), 'e' => 'AQAB'];

        self::assertSame($key->publicKeyPem, ProviderKey::admit($padded, self::all())?->publicKeyPem);
    }

    /**
     * Rows of `[modulus, exponent, bits, what the DER holds]`: an integer gets
     * a leading zero only when its top bit is set, and a length of 128 bytes or
     * more is written in the long form.
     *
     * @return iterable<string, array{0: string, 1: int, 2: string}>
     */
    public static function provideEncodings(): iterable
    {
        yield from [
            'under the top bit' => ["\x7f" . str_repeat("\xff", 254) . "\xfb", 2047, "\x02\x82\x01\x00\x7f"],
            'at the top bit'    => ["\x80" . str_repeat("\xff", 254) . "\xfb", 2048, "\x02\x82\x01\x01\x00\x80"],
            'a length of 127'   => ["\x7f" . str_repeat("\xff", 125) . "\xfb", 1015, "\x02\x7f\x7f"],
            'a length of 128'   => ["\x7f" . str_repeat("\xff", 126) . "\xfb", 1023, "\x02\x81\x80\x7f"],
        ];
    }

    /**
     * An RSA key is encoded exactly as DER writes it, which OpenSSL reads back
     * at its size.
     *
     * @param  string  $modulus
     * @param  int  $bits
     * @param  string  $integer
     * @return void
     */
    #[DataProvider('provideEncodings')]
    public function testAnRsaKeyIsEncodedAsDerWritesIt(string $modulus, int $bits, string $integer): void
    {
        $encoded = PublicKeyEncoding::rsa($modulus, "\x01\x00\x01");

        self::assertNotNull($encoded);
        self::assertSame($bits, $encoded['bits']);

        $body = str_replace(["-----BEGIN PUBLIC KEY-----\n", "-----END PUBLIC KEY-----\n", "\n"], '', $encoded['pem']);

        self::assertStringContainsString($integer, (string) base64_decode($body, true));
    }

    /**
     * Rows of `[curve, x, y]`: a point with no key on the curve the package
     * reads: the curve is not one, or a coordinate is not its length.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideRefusedPoints(): iterable
    {
        $coordinate = str_repeat("\x01", 32);

        yield from [
            'an unknown curve' => ['P-192', $coordinate, $coordinate],
            'a short x'        => ['P-256', str_repeat("\x01", 31), $coordinate],
            'a short y'        => ['P-256', $coordinate, str_repeat("\x01", 31)],
            'a long x'         => ['P-256', str_repeat("\x01", 33), $coordinate],
            'a long y'         => ['P-256', $coordinate, str_repeat("\x01", 33)],
        ];
    }

    /**
     * A point that is not of the curve's size gives no key.
     *
     * @param  string  $curve
     * @param  string  $x
     * @param  string  $y
     * @return void
     */
    #[DataProvider('provideRefusedPoints')]
    public function testAPointOfTheWrongSizeGivesNoKey(string $curve, string $x, string $y): void
    {
        self::assertNull(PublicKeyEncoding::ec($curve, $x, $y));
    }

    /**
     * Every algorithm.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList
     */
    private static function all(): AlgorithmAllowList
    {
        return AlgorithmAllowList::of(array_keys(AlgorithmAllowList::ALGORITHMS));
    }

    /**
     * A key of the kind, generated once: `rsa`, `1024`, or a curve.
     *
     * @param  string  $kind
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(string $kind): FakeSigningKey
    {
        return self::$keys[$kind] ??= match ($kind) {
            'rsa'   => FakeSigningKey::rsa('k1'),
            '1024'  => FakeSigningKey::rsa('s1', 1024),
            default => FakeSigningKey::ec('e1', $kind),
        };
    }
}
