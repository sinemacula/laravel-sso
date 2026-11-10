<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Oidc;

use Random\RandomException;

/**
 * RSASSA-PSS (RFC 8017 §8.1, §9.1) built by hand on OpenSSL's raw RSA, for the
 * fake OpenID provider (SSO-12.4): PHP's `openssl_sign()` signs PKCS #1 v1.5
 * only, and the provider must make PS256, PS384 and PS512 tokens without the
 * package's JOSE library, so a token the package accepts was not made by the
 * code that checks it. MGF1 uses the message's hash, and the salt is as long as
 * the hash, as RFC 7518 §3.5 requires.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PssSignature
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The PSS signature of the message with the PEM private key of the modulus
     * size given, in bits.
     *
     * @param  string  $message
     * @param  string  $privateKeyPem
     * @param  int  $modulusBits
     * @param  string  $hash
     * @return string
     *
     * @throws \LogicException
     */
    public static function sign(string $message, #[\SensitiveParameter] string $privateKeyPem, int $modulusBits, string $hash): string
    {
        $hashLength = strlen(hash($hash, '', true));
        $emBits     = $modulusBits - 1;
        $emLength   = intdiv($emBits + 7, 8);
        $salt       = self::salt($hashLength);
        $digest     = hash($hash, str_repeat("\x00", 8) . hash($hash, $message, true) . $salt, true);
        $block      = str_repeat("\x00", $emLength - 2 * $hashLength - 2) . "\x01" . $salt;
        $masked     = self::cleared($block ^ self::mgf1($digest, strlen($block), $hash), $emLength, $emBits);
        $encoded    = str_pad($masked . $digest . "\xbc", intdiv($modulusBits + 7, 8), "\x00", STR_PAD_LEFT);

        return self::encrypted($encoded, $privateKeyPem);
    }

    /**
     * Whether the PSS signature of the message verifies with the PEM public
     * key.
     *
     * @param  string  $message
     * @param  string  $signature
     * @param  string  $publicKeyPem
     * @param  string  $hash
     * @return bool
     */
    public static function verify(string $message, string $signature, string $publicKeyPem, string $hash): bool
    {
        $key     = openssl_pkey_get_public($publicKeyPem);
        $details = $key === false ? null : openssl_pkey_get_details($key);

        if (!is_array($details) || !openssl_public_decrypt($signature, $encoded, $publicKeyPem, OPENSSL_NO_PADDING)) {
            return false;
        }

        $emBits   = (int) $details['bits'] - 1;
        $emLength = intdiv($emBits + 7, 8);

        return self::isEncoding(substr((string) $encoded, -$emLength), $message, $emBits, $hash);
    }

    /**
     * A random salt of the length given.
     *
     * @param  int<1, max>  $length
     * @return string
     *
     * @throws \LogicException
     */
    private static function salt(int $length): string
    {
        try {
            return random_bytes($length);
        } catch (RandomException $exception) {
            throw new \LogicException('The fake provider could not make a salt.', 0, $exception);
        }
    }

    /**
     * The raw RSA private operation on the encoded message.
     *
     * @param  string  $encoded
     * @param  string  $privateKeyPem
     * @return string
     *
     * @throws \LogicException
     */
    private static function encrypted(string $encoded, #[\SensitiveParameter] string $privateKeyPem): string
    {
        if (!openssl_private_encrypt($encoded, $signature, $privateKeyPem, OPENSSL_NO_PADDING)) {
            throw new \LogicException('The fake provider could not sign.');
        }

        return (string) $signature;
    }

    /**
     * Whether the encoded message is the PSS encoding of the message.
     *
     * @param  string  $encoded
     * @param  string  $message
     * @param  int  $emBits
     * @param  string  $hash
     * @return bool
     */
    private static function isEncoding(string $encoded, string $message, int $emBits, string $hash): bool
    {
        $hashLength = strlen(hash($hash, '', true));
        $emLength   = strlen($encoded);
        $masked     = substr($encoded, 0, $emLength - $hashLength - 1);
        $digest     = substr($encoded, $emLength - $hashLength - 1, $hashLength);
        $block      = self::cleared($masked ^ self::mgf1($digest, strlen($masked), $hash), $emLength, $emBits);
        $padding    = str_repeat("\x00", $emLength - 2 * $hashLength - 2) . "\x01";
        $salt       = substr($block, -$hashLength);
        $expected   = hash($hash, str_repeat("\x00", 8) . hash($hash, $message, true) . $salt, true);

        return $encoded[-1] === "\xbc" && str_starts_with($block, $padding) && hash_equals($expected, $digest);
    }

    /**
     * The masked block with the bits above the encoding's size cleared.
     *
     * @param  string  $block
     * @param  int  $emLength
     * @param  int  $emBits
     * @return string
     */
    private static function cleared(string $block, int $emLength, int $emBits): string
    {
        $block[0] = chr(ord($block[0]) & (0xFF >> (8 * $emLength - $emBits)));

        return $block;
    }

    /**
     * MGF1 of the seed to the length, with the hash.
     *
     * @param  string  $seed
     * @param  int  $length
     * @param  string  $hash
     * @return string
     */
    private static function mgf1(string $seed, int $length, string $hash): string
    {
        $mask = '';

        for ($counter = 0; strlen($mask) < $length; $counter++) {
            $mask .= hash($hash, $seed . pack('N', $counter), true);
        }

        return substr($mask, 0, $length);
    }
}
