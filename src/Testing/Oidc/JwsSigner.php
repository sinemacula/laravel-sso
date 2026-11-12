<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Oidc;

/**
 * Builds and checks compact JWS with OpenSSL alone for the fake provider, so
 * tokens are made independently of the JOSE library that verifies them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class JwsSigner
{
    /** @var array<int, string> The hash of each size. */
    private const array HASHES = [256 => 'sha256', 384 => 'sha384', 512 => 'sha512'];

    /** @var array<int, int> The bytes of each of `R` and `S`, by `ES*` size. */
    private const array ECDSA_BYTES = [256 => 32, 384 => 48, 512 => 66];

    /** @var array<string, int> OpenSSL's digest of each hash. */
    private const array DIGESTS = ['sha256' => OPENSSL_ALGO_SHA256, 'sha384' => OPENSSL_ALGO_SHA384, 'sha512' => OPENSSL_ALGO_SHA512];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Sign a compact JWS; a string header or payload is encoded as given, so a
     * test can repeat a member.
     *
     * @param  array<string, mixed>|string  $header
     * @param  array<array-key, mixed>|string  $payload
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $key
     * @param  ?string  $algorithm
     * @return string
     *
     * @throws \LogicException
     */
    public static function sign(array|string $header, array|string $payload, FakeSigningKey $key, ?string $algorithm = null): string
    {
        $input = self::input($header, $payload);

        return $input . '.' . self::encode(self::signature($input, $key, $algorithm ?? self::algorithmOf($header)));
    }

    /**
     * A JWS with an HMAC signature, as a confused verifier would accept it.
     *
     * @param  array<string, mixed>|string  $header
     * @param  array<array-key, mixed>|string  $payload
     * @param  string  $secret
     * @param  string  $hash
     * @return string
     */
    public static function hmac(array|string $header, array|string $payload, #[\SensitiveParameter] string $secret, string $hash = 'sha256'): string
    {
        $input = self::input($header, $payload);

        return $input . '.' . self::encode(hash_hmac($hash, $input, $secret, true));
    }

    /**
     * A JWS with an empty signature, as `alg` `none` has it.
     *
     * @param  array<string, mixed>|string  $header
     * @param  array<array-key, mixed>|string  $payload
     * @return string
     */
    public static function unsigned(array|string $header, array|string $payload): string
    {
        return self::input($header, $payload) . '.';
    }

    /**
     * Whether a JWS the package signed verifies with the PEM public key.
     *
     * @param  string  $token
     * @param  string  $publicKeyPem
     * @return bool
     */
    public static function verify(string $token, string $publicKeyPem): bool
    {
        $parts     = explode('.', $token);
        $header    = count($parts) === 3 ? json_decode(self::decode($parts[0]), true) : null;
        $algorithm = is_array($header) && is_string($header['alg'] ?? null) ? $header['alg'] : '';
        $hash      = self::HASHES[substr($algorithm, 2)] ?? null;

        if ($hash === null) {
            return false;
        }

        $input     = $parts[0] . '.' . $parts[1];
        $signature = self::decode($parts[2]);

        return match (substr($algorithm, 0, 2)) {
            'RS'    => openssl_verify($input, $signature, $publicKeyPem, self::DIGESTS[$hash]) === 1,
            'PS'    => PssSignature::verify($input, $signature, $publicKeyPem, $hash),
            'ES'    => openssl_verify($input, self::der($signature), $publicKeyPem, self::DIGESTS[$hash]) === 1,
            default => false,
        };
    }

    /**
     * Encode the bytes as unpadded base64url.
     *
     * @param  string  $bytes
     * @return string
     */
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Decode unpadded base64url, or return an empty string.
     *
     * @param  string  $value
     * @return string
     */
    public static function decode(string $value): string
    {
        return (string) base64_decode(strtr($value, '-_', '+/'), true);
    }

    /**
     * Sign the input with the key by the algorithm.
     *
     * @param  string  $input
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $key
     * @param  string  $algorithm
     * @return string
     *
     * @throws \LogicException
     */
    private static function signature(string $input, FakeSigningKey $key, string $algorithm): string
    {
        $size = substr($algorithm, 2);
        $hash = self::HASHES[$size] ?? '';

        return match ($hash === '' ? '' : substr($algorithm, 0, 2)) {
            'RS'    => self::pkcs1($input, $key, $hash),
            'PS'    => self::pss($input, $key, $hash),
            'ES'    => self::ecdsa($input, $key, $hash, self::ECDSA_BYTES[$size]),
            default => self::unsupported($algorithm),
        };
    }

    /**
     * Refuse an algorithm the fake does not sign.
     *
     * @param  string  $algorithm
     * @return never
     *
     * @throws \LogicException
     */
    private static function unsupported(string $algorithm): never
    {
        throw new \LogicException(sprintf('The fake provider cannot sign [%s].', $algorithm));
    }

    /**
     * The `alg` of an array header, or an empty string.
     *
     * @param  array<string, mixed>|string  $header
     * @return string
     */
    private static function algorithmOf(array|string $header): string
    {
        $algorithm = is_array($header) ? ($header['alg'] ?? null) : null;

        return is_string($algorithm) ? $algorithm : '';
    }

    /**
     * The signing input; a string part is taken as the JSON text given.
     *
     * @param  array<string, mixed>|string  $header
     * @param  array<array-key, mixed>|string  $payload
     * @return string
     */
    private static function input(array|string $header, array|string $payload): string
    {
        $json = static fn (array|string $part): string => is_string($part) ? $part : json_encode($part, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        return self::encode($json($header)) . '.' . self::encode($json($payload));
    }

    /**
     * An RSA PKCS #1 v1.5 signature.
     *
     * @param  string  $input
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $key
     * @param  string  $hash
     * @return string
     *
     * @throws \LogicException
     */
    private static function pkcs1(string $input, FakeSigningKey $key, string $hash): string
    {
        if (!openssl_sign($input, $signature, $key->privateKeyPem, self::DIGESTS[$hash])) {
            throw new \LogicException('The fake provider could not sign.');
        }

        return (string) $signature;
    }

    /**
     * An RSASSA-PSS signature.
     *
     * @param  string  $input
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $key
     * @param  string  $hash
     * @return string
     *
     * @throws \LogicException
     */
    private static function pss(string $input, FakeSigningKey $key, string $hash): string
    {
        return PssSignature::sign($input, $key->privateKeyPem, $key->bits, $hash);
    }

    /**
     * An ECDSA signature as `R || S` padded to the algorithm's length whatever
     * the key's curve, so a P-256 key can sign an `ES512` header.
     *
     * @param  string  $input
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $key
     * @param  string  $hash
     * @param  int  $length
     * @return string
     *
     * @throws \LogicException
     */
    private static function ecdsa(string $input, FakeSigningKey $key, string $hash, int $length): string
    {
        if (!openssl_sign($input, $der, $key->privateKeyPem, self::DIGESTS[$hash])) {
            throw new \LogicException('The fake provider could not sign.');
        }

        $raw    = '';
        $offset = ord($der[1]) === 0x81 ? 3 : 2;

        for ($integer = 0; $integer < 2; $integer++) {
            $size = ord($der[$offset + 1]);
            $raw .= str_pad(ltrim(substr($der, $offset + 2, $size), "\x00"), $length, "\x00", STR_PAD_LEFT);
            $offset += 2 + $size;
        }

        return $raw;
    }

    /**
     * Convert an `R || S` signature to DER.
     *
     * @param  string  $raw
     * @return string
     */
    private static function der(string $raw): string
    {
        $members = '';

        foreach (str_split($raw, max(1, intdiv(strlen($raw), 2))) as $integer) {
            $integer = ltrim($integer, "\x00");
            $integer = $integer === '' || ord($integer[0]) > 0x7F ? "\x00" . $integer : $integer;
            $members .= "\x02" . chr(strlen($integer)) . $integer;
        }

        $length = strlen($members);

        return "\x30" . ($length < 0x80 ? chr($length) : "\x81" . chr($length)) . $members;
    }
}
