<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Oidc;

/**
 * Builds and checks compact JWS by hand for the fake OpenID provider
 * (SSO-12.4), with OpenSSL alone and never the package's JOSE library, so what
 * the package verifies is made independently of how it verifies it: `RS*` with
 * PKCS #1 v1.5, `PS*` with RSASSA-PSS (RFC 8017 §8.1, MGF1 with the same hash,
 * a salt as long as the hash) built on raw RSA, and `ES*` with the `R || S`
 * form of RFC 7518 §3.4. `hmac()` and `unsigned()` build the tokens a provider
 * must never get accepted: HMAC with any secret (a public key's PEM, say) and
 * `none`.
 *
 * `sign()` takes the header and payload as arrays, which it encodes, or as JSON
 * text, which it encodes as given, so a test can repeat a member or nest a
 * duplicate. `verify()` checks a client assertion the package signed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class JwsSigner
{
    /** @var array<int, string> The hash of each size. */
    private const array HASHES = [256 => 'sha256', 384 => 'sha384', 512 => 'sha512'];

    /** @var array<int, int> The bytes of each of `R` and `S`, by the size of the `ES*` algorithm. */
    private const array ECDSA_BYTES = [256 => 32, 384 => 48, 512 => 66];

    /** @var array<string, int> OpenSSL's digest of each hash. */
    private const array DIGESTS = ['sha256' => OPENSSL_ALGO_SHA256, 'sha384' => OPENSSL_ALGO_SHA384, 'sha512' => OPENSSL_ALGO_SHA512];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A compact JWS of the header and payload signed with the key by the
     * algorithm the header's `alg` names (`RS*`, `PS*` or `ES*`).
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
     * A compact JWS of the header and payload with an HMAC signature under the
     * secret, as a confused verifier would accept it.
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
     * A compact JWS of the header and payload with an empty signature, as `alg`
     * `none` has it.
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
     * Whether the compact JWS verifies with the PEM public key by the algorithm
     * its header names.
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
     * Unpadded base64url of the bytes.
     *
     * @param  string  $bytes
     * @return string
     */
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * The bytes of unpadded base64url, or an empty string.
     *
     * @param  string  $value
     * @return string
     */
    public static function decode(string $value): string
    {
        return (string) base64_decode(strtr($value, '-_', '+/'), true);
    }

    /**
     * The signature of the input with the key by the algorithm.
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
     * The `alg` a header given as an array names, or none.
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
     * The signing input of the header and payload, each encoded from an array
     * or taken as the JSON text given.
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
     * An ECDSA signature as `R || S`, each the length the algorithm names,
     * whatever curve the key is on (so a P-256 key can sign an `ES512` header,
     * as an attacker would).
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
     * The DER `SEQUENCE` of two `INTEGER`s from an `R || S` signature.
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
