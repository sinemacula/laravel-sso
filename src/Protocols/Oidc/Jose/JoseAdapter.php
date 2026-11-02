<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

use Carbon\CarbonImmutable;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * The package's JOSE adapter (SSO-7.3, RFC 7523,
 * `docs/design/jose-adapter.md`): the one class that calls
 * `web-token/jwt-library`, to check an ID token's signature with one stored key
 * and to sign a `private_key_jwt` client assertion. Everything the library
 * leaves out, or does in a way the package does not accept, is the adapter's
 * own, in this namespace: the token is read by `CompactToken` (compact only,
 * capped, no JWE, `crit` and `b64` refused, repeated JSON members refused), the
 * key admitted by `ProviderKey` and chosen by `ProviderKeySet::select()` (exact
 * `kid`, never the library's key set), and every time and claim checked by the
 * package against its clock (`TimeClaims` and the ID token rules), never by the
 * library.
 *
 * `verify()` builds a `JWSVerifier` for the call, with an `AlgorithmManager`
 * holding only the connection's allow-list: `none` and HMAC are never
 * registered, so the library cannot run them whatever a token's header says. It
 * checks first that the key fits the token's algorithm (`ProviderKey::fits()`)
 * and that the library reads the same protected header; anything the library
 * throws is a signature that does not verify, so it fails closed.
 *
 * `signClientAssertion()` signs RFC 7523 §3's claims with the connection's
 * current key: `iss` and `sub` the client id, `aud` the token endpoint exactly,
 * a fresh 256-bit `jti`, `iat` now and `exp` `ASSERTION_LIFETIME_SECONDS`
 * later, under the header `alg` (the algorithm the connection pinned, or the
 * key's default: `PS256` or `RS256` for an RSA key, `ES256` for a P-256 key,
 * `ClientKey`), `kid` (its thumbprint) and `typ` `JWT`. The algorithm is never
 * negotiated and an assertion is never retried under another. Anything the
 * library throws while it signs is answered with a package exception that
 * carries nothing of the library's: no previous exception and no frame holding
 * the private JWK.
 *
 * Nothing it builds outlives the call: it keeps no verifier, key, clock or
 * token in a property (SSO-11.2), and the library declares no static state.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class JoseAdapter
{
    /** @var int How long a client assertion is valid, in seconds after its `iat`. */
    public const int ASSERTION_LIFETIME_SECONDS = 60;

    /** @var int The bytes of randomness in a client assertion's `jti`. */
    public const int JTI_BYTES = 32;

    /** @var array<string, class-string<\Jose\Component\Signature\Algorithm\SignatureAlgorithm>> The library's class of each algorithm the package can register: asymmetric only. */
    private const array ALGORITHMS = [
        'RS256' => RS256::class,
        'RS384' => RS384::class,
        'RS512' => RS512::class,
        'PS256' => PS256::class,
        'PS384' => PS384::class,
        'PS512' => PS512::class,
        'ES256' => ES256::class,
        'ES384' => ES384::class,
        'ES512' => ES512::class,
    ];

    /**
     * Whether the token's signature verifies with the key, for an algorithm on
     * the allow-list that the key fits.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken  $token
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey  $key
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @return bool
     */
    public function verify(CompactToken $token, ProviderKey $key, AlgorithmAllowList $allowed): bool
    {
        if (!$key->fits($token->algorithm(), $allowed)) {
            return false;
        }

        try {
            $jws = (new CompactSerializer)->unserialize($token->compact());

            return $jws->getSignature(0)->getProtectedHeader() === $token->header()
                && (new JWSVerifier(self::manager($allowed->names)))->verifyWithKey($jws, new JWK($key->toArray()), 0);
            // The library declares no @throws, though a value it cannot read
            // throws.
            // @phpstan-ignore catch.neverThrown
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * A client assertion for the client at the token endpoint, signed now with
     * the PEM private key given, under the algorithm the connection pinned or,
     * with none, the key's default.
     *
     * @param  string  $clientId
     * @param  string  $tokenEndpoint
     * @param  \SineMacula\Laravel\Sso\Secrets\Secret  $privateKeyPem
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?string  $algorithm
     * @return \SineMacula\Laravel\Sso\Secrets\Secret
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     */
    public function signClientAssertion(string $clientId, string $tokenEndpoint, Secret $privateKeyPem, CarbonImmutable $now, ?string $algorithm = null): Secret
    {
        self::assertNamed($clientId, $tokenEndpoint);

        $key      = ClientKey::fromPrivateKey($privateKeyPem, $algorithm);
        $issuedAt = $now->getTimestamp();
        $claims   = [
            'iss' => $clientId,
            'sub' => $clientId,
            'aud' => $tokenEndpoint,
            'jti' => Base64Url::encode(random_bytes(self::JTI_BYTES)),
            'iat' => $issuedAt,
            'exp' => $issuedAt + self::ASSERTION_LIFETIME_SECONDS,
        ];

        return new Secret(self::signed($key, (string) json_encode($claims, JSON_UNESCAPED_SLASHES)));
    }

    /**
     * The payload signed with the key, compact. What the library throws is
     * replaced, since its frames hold the private JWK.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ClientKey  $key
     * @param  string  $payload
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function signed(ClientKey $key, string $payload): string
    {
        try {
            return self::built($key, $payload);
        } catch (\Throwable) {
            throw new \InvalidArgumentException('The client assertion could not be signed.');
        }
    }

    /**
     * The payload signed by the library with the key, compact. The library
     * declares no @throws, though a key it cannot use throws.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ClientKey  $key
     * @param  string  $payload
     * @return string
     *
     * @throws \Throwable
     */
    private static function built(ClientKey $key, string $payload): string // @phpstan-ignore throws.unusedType
    {
        $jws = (new JWSBuilder(self::manager([$key->algorithm])))
            ->create()
            ->withPayload($payload)
            ->addSignature(new JWK($key->privateJwk()), ['alg' => $key->algorithm, 'kid' => $key->keyId(), 'typ' => 'JWT'])
            ->build();

        return (new CompactSerializer)->serialize($jws, 0);
    }

    /**
     * Refuse a client assertion with no client or no token endpoint: the
     * caller's mistake.
     *
     * @param  string  $clientId
     * @param  string  $tokenEndpoint
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertNamed(string $clientId, string $tokenEndpoint): void
    {
        if ($clientId === '' || $tokenEndpoint === '') {
            throw new \InvalidArgumentException('A client assertion names its client and its token endpoint.');
        }
    }

    /**
     * An algorithm manager holding the algorithms named and nothing else.
     *
     * @param  list<string>  $names
     * @return \Jose\Component\Core\AlgorithmManager
     */
    private static function manager(array $names): AlgorithmManager
    {
        return new AlgorithmManager(array_map(static fn (string $name): SignatureAlgorithm => new (self::ALGORITHMS[$name]), $names));
    }
}
