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
 * The only class that calls `web-token/jwt-library`: verifies an ID token
 * signature with one key and signs `private_key_jwt` client assertions.
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

    /** @var array<string, class-string<\Jose\Component\Signature\Algorithm\SignatureAlgorithm>> The library class of each registrable algorithm, asymmetric only. */
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
     * Whether the signature verifies with the key, under only the allow-listed
     * algorithms; anything the library throws fails closed.
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
            // The library declares no @throws, though unreadable input throws
            // @phpstan-ignore catch.neverThrown
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Sign an RFC 7523 client assertion under the pinned algorithm, or the
     * key's default when none is pinned.
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
     * Sign the payload, replacing anything the library throws since its frames
     * hold the private JWK.
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
     * Sign the payload with the library, which throws undeclared on a key it
     * cannot use.
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
     * Refuse a client assertion with no client or token endpoint.
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
     * An algorithm manager holding only the named algorithms.
     *
     * @param  list<string>  $names
     * @return \Jose\Component\Core\AlgorithmManager
     */
    private static function manager(array $names): AlgorithmManager
    {
        return new AlgorithmManager(array_map(static fn (string $name): SignatureAlgorithm => new (self::ALGORITHMS[$name]), $names));
    }
}
