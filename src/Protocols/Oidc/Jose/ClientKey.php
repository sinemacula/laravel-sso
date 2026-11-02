<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * One of a connection's own `private_key_jwt` keys (SSO-2.4, SSO-2.7, RFC
 * 7523) as a JWK: the algorithm the package signs client assertions with, its
 * `kid`, which is the RFC 7638 thumbprint of its public half and so stays the
 * same for as long as the key does, and its public JWK, which the identity
 * provider registers (SSO-5.9).
 *
 * The algorithm is the connection's pinned one, given by the caller, or the
 * key's default: an RSA key of at least 2048 bits signs with `PS256`, or
 * `RS256` when pinned to it, and an elliptic curve key on P-256 signs with
 * `ES256` alone. The assertion's header and the published JWK's `alg` are both
 * that algorithm, and the `kid` does not depend on it.
 *
 * `fromPrivateKey()` reads the private half, for the call that signs, and holds
 * it in a `\SensitiveParameterValue` that no dump shows; the object refuses to
 * be serialised. `publicJwk()` reads a public key alone, and its `kid` is the
 * one the private half signs under. Any other key, or a pinned algorithm the
 * key cannot sign with, is a misconfiguration (an `InvalidArgumentException`):
 * the package generates only these keys and refuses such a setting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ClientKey
{
    /** @var string The algorithm an RSA key signs with unless it is pinned to another. */
    public const string RSA_ALGORITHM = 'PS256';

    /** @var string The other algorithm an RSA key may be pinned to. */
    public const string RSA_ALTERNATIVE_ALGORITHM = 'RS256';

    /** @var string The algorithm a P-256 key signs with. */
    public const string EC_ALGORITHM = 'ES256';

    /** @var string The refusal of any other key. */
    private const string UNSUPPORTED = 'A client assertion key is an RSA key of at least 2048 bits or an elliptic curve key on P-256.';

    /** @var string The refusal of a pinned algorithm the key cannot sign with. */
    private const string INCOMPATIBLE = 'A client assertion algorithm must fit its key: PS256 or RS256 for an RSA key, ES256 for a P-256 key.';

    /** @var array<string, string> The RSA members of a private JWK, by the name OpenSSL gives each. */
    private const array RSA_PRIVATE = ['d' => 'd', 'p' => 'p', 'q' => 'q', 'dmp1' => 'dp', 'dmq1' => 'dq', 'iqmp' => 'qi'];

    /** @var \SensitiveParameterValue The private JWK, when the key was read from its private half. */
    private \SensitiveParameterValue $privateJwk;

    /**
     * Constructor.
     *
     * @param  string  $algorithm
     * @param  array<string, string>  $publicJwk
     * @param  array<string, string>  $privateMembers
     */
    private function __construct(

        /** The algorithm the key signs with: `PS256`, `RS256` or `ES256`. */
        public string $algorithm,

        /** The public JWK, with its `kid`, `use` and `alg`. */
        public array $publicJwk,

        // The private members; held wrapped
        #[\SensitiveParameter]
        array $privateMembers = [],
    ) {
        $this->privateJwk = new \SensitiveParameterValue([...$publicJwk, ...$privateMembers]);
    }

    /**
     * What a dump shows: the algorithm and the public JWK, never a private
     * member.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['algorithm' => $this->algorithm, 'public_jwk' => $this->publicJwk, 'private_jwk' => '[redacted]'];
    }

    /**
     * Refuse to be serialised: the private half lives only for the call that
     * signs with it.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A client assertion key cannot be serialised.');
    }

    /**
     * Refuse to be unserialised.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     * @SuppressWarnings("php:S1172")
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A client assertion key cannot be unserialised.');
    }

    /**
     * The key whose PEM private half is given, signing with the algorithm it is
     * pinned to, or its default.
     *
     * @param  \SineMacula\Laravel\Sso\Secrets\Secret  $privateKeyPem
     * @param  ?string  $algorithm
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromPrivateKey(Secret $privateKeyPem, ?string $algorithm = null): self
    {
        $key     = openssl_pkey_get_private($privateKeyPem->reveal());
        $details = $key === false ? null : openssl_pkey_get_details($key);

        if (!is_array($details)) {
            throw new \InvalidArgumentException(self::UNSUPPORTED);
        }

        [$signing, $public] = self::publicOf($details, $algorithm);

        return new self($signing, $public, self::privateOf($details));
    }

    /**
     * The public JWK of the PEM public key, under the `kid` its private half
     * signs with and the `alg` it is pinned to, or its default.
     *
     * @param  string  $publicKeyPem
     * @param  ?string  $algorithm
     * @return array<string, string>
     *
     * @throws \InvalidArgumentException
     */
    public static function publicJwk(string $publicKeyPem, ?string $algorithm = null): array
    {
        $key     = openssl_pkey_get_public($publicKeyPem);
        $details = $key === false ? null : openssl_pkey_get_details($key);

        if (!is_array($details)) {
            throw new \InvalidArgumentException(self::UNSUPPORTED);
        }

        return self::publicOf($details, $algorithm)[1];
    }

    /**
     * The key's `kid`.
     *
     * @return string
     */
    public function keyId(): string
    {
        return $this->publicJwk['kid'];
    }

    /**
     * The private JWK, for the call that signs and nothing else.
     *
     * @return array<string, string>
     */
    public function privateJwk(): array
    {
        /** @var array<string, string> */
        return $this->privateJwk->getValue();
    }

    /**
     * The algorithm and the public JWK of the key OpenSSL describes, pinned to
     * the algorithm given, or its default.
     *
     * @param  array<array-key, mixed>  $details
     * @param  ?string  $pinned
     * @return array{0: string, 1: array<string, string>}
     *
     * @throws \InvalidArgumentException
     */
    private static function publicOf(#[\SensitiveParameter] array $details, ?string $pinned): array
    {
        $rsa = $details['rsa'] ?? null;
        $ec  = $details['ec']  ?? null;
        $big = ($details['bits'] ?? null) >= ProviderKey::MIN_RSA_BITS;

        [$allowed, $required] = match (true) {
            is_array($rsa) && $big                                         => [[self::RSA_ALGORITHM, self::RSA_ALTERNATIVE_ALGORITHM], self::rsaPublic($rsa)],
            is_array($ec)  && ($ec['curve_name'] ?? null) === 'prime256v1' => [[self::EC_ALGORITHM], self::ecPublic($ec)],
            default                                                        => throw new \InvalidArgumentException(self::UNSUPPORTED),
        };

        $algorithm = $pinned ?? $allowed[0];

        if (!in_array($algorithm, $allowed, true)) {
            throw new \InvalidArgumentException(self::INCOMPATIBLE);
        }

        $kid = Base64Url::encode(hash('sha256', (string) json_encode($required, JSON_UNESCAPED_SLASHES), true));

        return [$algorithm, [...$required, 'kid' => $kid, 'use' => 'sig', 'alg' => $algorithm]];
    }

    /**
     * The private members of the key OpenSSL describes.
     *
     * @param  array<array-key, mixed>  $details
     * @return array<string, string>
     */
    private static function privateOf(#[\SensitiveParameter] array $details): array
    {
        $ec = $details['ec'] ?? null;

        if (is_array($ec)) {
            return ['d' => self::coordinate($ec['d'] ?? '')];
        }

        $rsa     = $details['rsa'] ?? [];
        $members = [];

        foreach (self::RSA_PRIVATE as $from => $to) {
            $members[$to] = self::encoded(is_array($rsa) ? ($rsa[$from] ?? '') : '');
        }

        return $members;
    }

    /**
     * The required public members of an RSA key, in RFC 7638 order.
     *
     * @param  array<array-key, mixed>  $rsa
     * @return array<string, string>
     */
    private static function rsaPublic(#[\SensitiveParameter] array $rsa): array
    {
        return ['e' => self::encoded($rsa['e'] ?? ''), 'kty' => 'RSA', 'n' => self::encoded($rsa['n'] ?? '')];
    }

    /**
     * The required public members of a P-256 key, in RFC 7638 order.
     *
     * @param  array<array-key, mixed>  $ec
     * @return array<string, string>
     */
    private static function ecPublic(#[\SensitiveParameter] array $ec): array
    {
        return ['crv' => 'P-256', 'kty' => 'EC', 'x' => self::coordinate($ec['x'] ?? ''), 'y' => self::coordinate($ec['y'] ?? '')];
    }

    /**
     * A P-256 coordinate or scalar, padded to its 32 bytes and encoded.
     *
     * @param  mixed  $bytes
     * @return string
     */
    private static function coordinate(#[\SensitiveParameter] mixed $bytes): string
    {
        return self::encoded(str_pad(is_string($bytes) ? $bytes : '', 32, "\x00", STR_PAD_LEFT));
    }

    /**
     * The bytes, as unpadded base64url.
     *
     * @param  mixed  $bytes
     * @return string
     */
    private static function encoded(#[\SensitiveParameter] mixed $bytes): string
    {
        return Base64Url::encode(is_string($bytes) ? $bytes : '');
    }
}
