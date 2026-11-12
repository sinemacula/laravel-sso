<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

/**
 * Encodes an RSA or EC JWK as a PEM `SubjectPublicKeyInfo` and has OpenSSL read
 * it back, so only a key OpenSSL accepts is admitted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PublicKeyEncoding
{
    /** @var array<string, int> The bytes of each coordinate on each curve. */
    public const array COORDINATE_BYTES = ['P-256' => 32, 'P-384' => 48, 'P-521' => 66];

    /** @var string The DER `rsaEncryption` algorithm identifier with NULL parameters. */
    private const string RSA_ALGORITHM = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";

    /** @var string The DER of the `id-ecPublicKey` object identifier. */
    private const string EC_PUBLIC_KEY = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";

    /** @var array<string, string> The DER of each curve's object identifier, by its JWK name. */
    private const array CURVES = [
        'P-256' => "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        'P-384' => "\x06\x05\x2b\x81\x04\x00\x22",
        'P-521' => "\x06\x05\x2b\x81\x04\x00\x23",
    ];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The bits and PEM of the RSA key from big-endian modulus and exponent, or
     * `null` when OpenSSL refuses it.
     *
     * @param  string  $modulus
     * @param  string  $exponent
     * @return ?array{bits: int, pem: string}
     */
    public static function rsa(string $modulus, string $exponent): ?array
    {
        $key = self::sequence(self::integer($modulus) . self::integer($exponent));

        return self::details(self::sequence(self::RSA_ALGORITHM . self::bitString($key)));
    }

    /**
     * The bits and PEM of the EC key at the point, or `null` for an unknown
     * curve, a wrong coordinate length or a point OpenSSL refuses.
     *
     * @param  string  $curve
     * @param  string  $x
     * @param  string  $y
     * @return ?array{bits: int, pem: string}
     */
    public static function ec(string $curve, string $x, string $y): ?array
    {
        $bytes = self::COORDINATE_BYTES[$curve] ?? null;

        if ([strlen($x), strlen($y)] !== [$bytes, $bytes]) {
            return null;
        }

        $algorithm = self::sequence(self::EC_PUBLIC_KEY . self::CURVES[$curve]);

        return self::details(self::sequence($algorithm . self::bitString("\x04" . $x . $y)));
    }

    /**
     * The PEM of the DER `SubjectPublicKeyInfo`.
     *
     * @param  string  $der
     * @return string
     */
    private static function pem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /**
     * The bits OpenSSL reads from the DER and its PEM, or `null` when OpenSSL
     * refuses it.
     *
     * @param  string  $der
     * @return ?array{bits: int, pem: string}
     */
    private static function details(string $der): ?array
    {
        $pem     = self::pem($der);
        $key     = openssl_pkey_get_public($pem);
        $details = $key === false ? null : openssl_pkey_get_details($key);
        $bits    = is_array($details) ? ($details['bits'] ?? null) : null;

        return is_int($bits) ? ['bits' => $bits, 'pem' => $pem] : null;
    }

    /**
     * A DER `SEQUENCE` of the encoded members.
     *
     * @param  string  $members
     * @return string
     */
    private static function sequence(string $members): string
    {
        return "\x30" . self::length(strlen($members)) . $members;
    }

    /**
     * A DER `INTEGER` of the unsigned big-endian bytes.
     *
     * @param  string  $bytes
     * @return string
     */
    private static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        $bytes = $bytes === '' || ord($bytes[0]) > 0x7F ? "\x00" . $bytes : $bytes;

        return "\x02" . self::length(strlen($bytes)) . $bytes;
    }

    /**
     * A DER `BIT STRING` of the bytes, with no unused bits.
     *
     * @param  string  $bytes
     * @return string
     */
    private static function bitString(string $bytes): string
    {
        return "\x03" . self::length(strlen($bytes) + 1) . "\x00" . $bytes;
    }

    /**
     * A DER length.
     *
     * @param  int  $length
     * @return string
     */
    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = ltrim(pack('N', $length), "\x00");

        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}
