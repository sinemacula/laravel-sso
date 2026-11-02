<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

/**
 * One public key of an identity provider's JWKS that the package admits for ID
 * token signatures (SSO-7.3), admitted when the JWKS is read and again each
 * time a stored JWKS is read for use:
 *
 * - `kty` `RSA` or `EC`, never `oct` or anything else;
 * - public only: a key with a private member (`d`, `p`, `q`, `dp`, `dq`, `qi`,
 *   `oth`) or a symmetric `k` is not admitted;
 * - `kid`, when present, a non-empty string;
 * - `use`, when present, `sig`; `key_ops`, when present, a list of strings that
 *   includes `verify`;
 * - `alg`, when present, on the connection's allow-list and one the key fits;
 * - an RSA key of at least `MIN_RSA_BITS` with an odd public exponent of at
 *   least 3, or an elliptic curve key on P-256, P-384 or P-521 whose point
 *   OpenSSL accepts, each member canonical unpadded base64url.
 *
 * `fits()` is the check at use: the algorithm is on the allow-list, the key is
 * the type and curve it needs, and the key's own `alg`, when it has one, is
 * that algorithm. Its stored form (`toArray()`) holds the public members alone,
 * in a fixed order, and its RFC 7638 thumbprint tells a key replaced under the
 * same `kid` from the key it replaced. It holds no secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProviderKey
{
    /** @var int The smallest RSA modulus admitted, in bits. */
    public const int MIN_RSA_BITS = 2048;

    /** @var int The largest RSA modulus admitted, in bits. */
    public const int MAX_RSA_BITS = 16384;

    /** @var list<string> The members a public key never carries. */
    private const array PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

    /** @var array<string, list<string>> The members of each type's stored form, in its order. */
    private const array STORED_MEMBERS = [
        'RSA' => ['kty', 'kid', 'use', 'key_ops', 'alg', 'n', 'e'],
        'EC'  => ['kty', 'kid', 'use', 'key_ops', 'alg', 'crv', 'x', 'y'],
    ];

    /**
     * Constructor.
     *
     * @param  array<string, mixed>  $members
     * @param  int  $bits
     * @param  string  $publicKeyPem
     */
    private function __construct(

        /** The stored form: the public members, in a fixed order. */
        private array $members,

        /** The RSA modulus's or the curve's size, in bits. */
        public int $bits,

        /** The key as a PEM `SubjectPublicKeyInfo`. */
        public string $publicKeyPem,
    ) {}

    /**
     * The key the JWK gives, when the package admits it for the allow-list.
     *
     * @param  array<array-key, mixed>  $jwk
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @return ?self
     */
    public static function admit(array $jwk, AlgorithmAllowList $allowed): ?self
    {
        if (!self::hasAdmissibleMembers($jwk) || !self::isAdmissibleAlgorithm($jwk, $allowed)) {
            return null;
        }

        $details = ($jwk['kty'] ?? null) === 'RSA' ? self::rsa($jwk) : self::ec($jwk);

        return $details === null ? null : new self(self::stored($jwk), $details['bits'], $details['pem']);
    }

    /**
     * The key's `kid`, or `null` when it has none.
     *
     * @return ?string
     */
    public function keyId(): ?string
    {
        $kid = $this->members['kid'] ?? null;

        return is_string($kid) ? $kid : null;
    }

    /**
     * The key's type: `RSA` or `EC`.
     *
     * @return string
     */
    public function keyType(): string
    {
        $type = $this->members['kty'] ?? null;

        return is_string($type) ? $type : '';
    }

    /**
     * Whether the key may verify a signature of the algorithm under the
     * allow-list: the algorithm is allowed, the key is of the type and on the
     * curve it needs, and the key's own `alg`, when it has one, is it.
     *
     * @param  string  $algorithm
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @return bool
     */
    public function fits(string $algorithm, AlgorithmAllowList $allowed): bool
    {
        $own = $this->members['alg'] ?? $algorithm;

        return $allowed->allows($algorithm)
            && $own                                      === $algorithm
            && AlgorithmAllowList::keyTypeOf($algorithm) === $this->keyType()
            && AlgorithmAllowList::curveOf($algorithm)   === ($this->members['crv'] ?? null);
    }

    /**
     * The key's RFC 7638 thumbprint: the unpadded base64url SHA-256 of its
     * required public members.
     *
     * @return string
     */
    public function thumbprint(): string
    {
        $required = $this->keyType() === 'RSA' ? ['e', 'kty', 'n'] : ['crv', 'kty', 'x', 'y'];
        $members  = array_intersect_key($this->members, array_flip($required));

        ksort($members);

        return Base64Url::encode(hash('sha256', (string) json_encode($members, JSON_UNESCAPED_SLASHES), true));
    }

    /**
     * The stored form: the public members, in a fixed order.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->members;
    }

    /**
     * Whether the JWK is a public RSA or elliptic curve key whose `kid`, `use`
     * and `key_ops` the package admits.
     *
     * @param  array<array-key, mixed>  $jwk
     * @return bool
     */
    private static function hasAdmissibleMembers(array $jwk): bool
    {
        $kid     = array_key_exists('kid', $jwk) ? $jwk['kid'] : 'absent';
        $use     = array_key_exists('use', $jwk) ? $jwk['use'] : 'sig';
        $private = array_intersect(self::PRIVATE_MEMBERS, array_keys($jwk));
        $public  = in_array($jwk['kty'] ?? null, ['RSA', 'EC'], true) && $private === [];
        $keyed   = is_string($kid)                                    && $kid !== '';

        return $public && $keyed && $use === 'sig' && self::isVerifying($jwk);
    }

    /**
     * Whether the JWK's `key_ops`, when it has them, are a list of strings that
     * includes `verify`.
     *
     * @param  array<array-key, mixed>  $jwk
     * @return bool
     */
    private static function isVerifying(array $jwk): bool
    {
        if (!array_key_exists('key_ops', $jwk)) {
            return true;
        }

        $operations = $jwk['key_ops'];

        return is_array($operations) && array_is_list($operations) && array_filter($operations, is_string(...)) === $operations && in_array('verify', $operations, true);
    }

    /**
     * Whether the JWK's `alg`, when it has one, is on the allow-list and one
     * the key's type and curve fit.
     *
     * @param  array<array-key, mixed>  $jwk
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @return bool
     */
    private static function isAdmissibleAlgorithm(array $jwk, AlgorithmAllowList $allowed): bool
    {
        if (!array_key_exists('alg', $jwk)) {
            return true;
        }

        $algorithm = $jwk['alg'];

        return is_string($algorithm)
            && $allowed->allows($algorithm)
            && AlgorithmAllowList::keyTypeOf($algorithm) === $jwk['kty']
            && AlgorithmAllowList::curveOf($algorithm)   === ($jwk['crv'] ?? null);
    }

    /**
     * What OpenSSL reads from an RSA JWK of an admissible size and exponent, or
     * `null`.
     *
     * @param  array<array-key, mixed>  $jwk
     * @return ?array{bits: int, pem: string}
     */
    private static function rsa(array $jwk): ?array
    {
        $modulus  = self::member($jwk, 'n');
        $exponent = self::member($jwk, 'e');

        if ($modulus === null || $exponent === null || !self::isExponent($exponent) || array_key_exists('crv', $jwk)) {
            return null;
        }

        $details = PublicKeyEncoding::rsa($modulus, $exponent);
        $bits    = $details['bits'] ?? null;

        return $bits >= self::MIN_RSA_BITS && $bits <= self::MAX_RSA_BITS ? $details : null;
    }

    /**
     * What OpenSSL reads from an elliptic curve JWK on a curve the package
     * reads, or `null`.
     *
     * @param  array<array-key, mixed>  $jwk
     * @return ?array{bits: int, pem: string}
     */
    private static function ec(array $jwk): ?array
    {
        $curve = $jwk['crv'] ?? null;
        $x     = self::member($jwk, 'x');
        $y     = self::member($jwk, 'y');

        if (!is_string($curve) || $x === null || $y === null) {
            return null;
        }

        return PublicKeyEncoding::ec($curve, $x, $y);
    }

    /**
     * Whether the big-endian bytes are an odd exponent of at least 3, at most
     * eight bytes long.
     *
     * @param  string  $exponent
     * @return bool
     */
    private static function isExponent(string $exponent): bool
    {
        $exponent = ltrim($exponent, "\x00");

        return $exponent !== '' && strlen($exponent) <= 8 && (ord($exponent[-1]) & 1) === 1 && $exponent !== "\x01";
    }

    /**
     * The bytes a member holds as canonical unpadded base64url, or `null`.
     *
     * @param  array<array-key, mixed>  $jwk
     * @param  string  $name
     * @return ?string
     */
    private static function member(array $jwk, string $name): ?string
    {
        $value = $jwk[$name] ?? null;
        $bytes = is_string($value) ? Base64Url::decode($value) : null;

        return $bytes === '' ? null : $bytes;
    }

    /**
     * The stored form of an admitted JWK: its public members, in a fixed order.
     *
     * @param  array<array-key, mixed>  $jwk
     * @return array<string, mixed>
     */
    private static function stored(array $jwk): array
    {
        $names   = self::STORED_MEMBERS[($jwk['kty'] ?? null) === 'EC' ? 'EC' : 'RSA'];
        $ordered = array_map(static fn (string $name): mixed => $jwk[$name] ?? null, array_combine($names, $names));

        return array_filter($ordered, static fn (mixed $value): bool => $value !== null);
    }
}
