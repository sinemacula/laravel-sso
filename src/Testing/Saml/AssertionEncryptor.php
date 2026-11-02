<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Saml;

use Random\RandomException;

/**
 * Encrypts an assertion for the service provider's certificate, as the fake
 * SAML identity provider's `EncryptedAssertion` (SSO-12.4), seeded from the
 * library spike's fixture generator: AES-GCM or AES-CBC content encryption with
 * a random session key, carried by RSA-OAEP or, for a hostile case, RSA PKCS#1
 * v1.5 key transport. A test tool, with OpenSSL alone; the package decrypts
 * only through its SAML adapter.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AssertionEncryptor
{
    /** @var array<string, array{0: string, 1: string, 2: int}> Each data algorithm by short name: its URI, the OpenSSL cipher and the key length in bytes. */
    public const array DATA_ALGORITHMS = [
        'aes128-gcm' => ['http://www.w3.org/2009/xmlenc11#aes128-gcm', 'aes-128-gcm', 16],
        'aes192-gcm' => ['http://www.w3.org/2009/xmlenc11#aes192-gcm', 'aes-192-gcm', 24],
        'aes256-gcm' => ['http://www.w3.org/2009/xmlenc11#aes256-gcm', 'aes-256-gcm', 32],
        'aes128-cbc' => ['http://www.w3.org/2001/04/xmlenc#aes128-cbc', 'aes-128-cbc', 16],
        'aes256-cbc' => ['http://www.w3.org/2001/04/xmlenc#aes256-cbc', 'aes-256-cbc', 32],
    ];

    /** @var array<string, array{0: string, 1: int}> Each key transport by short name: its URI and the OpenSSL padding. */
    public const array KEY_TRANSPORTS = [
        'rsa-oaep-mgf1p' => ['http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p', OPENSSL_PKCS1_OAEP_PADDING],
        'rsa-oaep'       => ['http://www.w3.org/2009/xmlenc11#rsa-oaep', OPENSSL_PKCS1_OAEP_PADDING],
        'rsa-1_5'        => ['http://www.w3.org/2001/04/xmlenc#rsa-1_5', OPENSSL_PKCS1_PADDING],
    ];

    /** @var string The XML encryption namespace. */
    private const string NS_XENC = 'http://www.w3.org/2001/04/xmlenc#';

    /** @var string The XML signature namespace. */
    private const string NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * The `saml:EncryptedAssertion` carrying the serialised assertion,
     * encrypted for the certificate.
     *
     * @param  string  $assertion
     * @param  string  $certificate
     * @param  string  $keyTransport
     * @param  string  $data
     * @return string
     *
     * @throws \LogicException
     */
    public function encrypt(string $assertion, string $certificate, string $keyTransport = 'rsa-oaep-mgf1p', string $data = 'aes128-gcm'): string
    {
        [$dataUri, $cipher, $length] = self::DATA_ALGORITHMS[$data];
        [$transportUri, $padding]    = self::KEY_TRANSPORTS[$keyTransport];

        $key = self::random($length);

        if (!openssl_public_encrypt($key, $encryptedKey, $certificate, $padding)) {
            throw new \LogicException('The fake identity provider could not encrypt the session key.');
        }

        return '<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><xenc:EncryptedData xmlns:xenc="'
            . self::NS_XENC . '" Type="' . self::NS_XENC . 'Element"><xenc:EncryptionMethod Algorithm="' . $dataUri . '"/>'
            . '<ds:KeyInfo xmlns:ds="' . self::NS_DS . '"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="' . $transportUri . '"/>'
            . '<xenc:CipherData><xenc:CipherValue>' . base64_encode($encryptedKey) . '</xenc:CipherValue></xenc:CipherData>'
            . '</xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>' . base64_encode(self::ciphertext($assertion, $cipher, $key))
            . '</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>';
    }

    /**
     * The ciphertext as XML encryption carries it: the initialisation vector,
     * the ciphertext and, for GCM, the tag.
     *
     * @param  string  $plaintext
     * @param  string  $cipher
     * @param  string  $key
     * @return string
     *
     * @throws \LogicException
     */
    private static function ciphertext(string $plaintext, string $cipher, #[\SensitiveParameter] string $key): string
    {
        $gcm        = str_ends_with($cipher, '-gcm');
        $iv         = self::random($gcm ? 12 : 16);
        $tag        = '';
        $ciphertext = $gcm
            ? openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag)
            : openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv);

        if ($ciphertext === false) {
            throw new \LogicException('The fake identity provider could not encrypt the assertion.');
        }

        return $iv . $ciphertext . $tag;
    }

    /**
     * Random bytes of the length.
     *
     * @param  int<1, max>  $length
     * @return string
     *
     * @throws \LogicException
     */
    private static function random(int $length): string
    {
        try {
            return random_bytes($length);
        } catch (RandomException) {
            throw new \LogicException('The fake identity provider has no source of randomness.');
        }
    }
}
