<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

/**
 * An admitted public RSA or EC signing key from a provider's JWKS. It is
 * admitted on import and again on every read of the stored JWKS.
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

    /** @var list<string> The private or symmetric members a public key never carries. */
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
     * Admit the JWK under the allow-list, or return `null`.
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
     * Whether the key may verify the algorithm: allowed, of the right type and
     * curve, and matching the key's own `alg` if any.
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
     * The RFC 7638 thumbprint, which tells a key replaced under the same `kid`
     * from the original.
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
     * Whether the JWK is a public RSA or EC key with admissible `kid`, `use`
     * and `key_ops`.
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
     * Whether any `key_ops` is a list of strings including `verify`.
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
     * Whether any `alg` is allowed and fits the key's type and curve.
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
     * What OpenSSL reads from an RSA JWK of admissible size and exponent.
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
     * What OpenSSL reads from an EC JWK on a supported curve.
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
     * Whether the big-endian bytes are an odd exponent of at least 3, at most 8
     * bytes long.
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
     * Decode a canonical unpadded base64url member, or return `null`.
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
     * The stored form of an admitted JWK.
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
