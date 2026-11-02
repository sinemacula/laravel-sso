<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Keys;

/**
 * Throwaway identity provider certificates for the key tests, generated with
 * PHP's OpenSSL extension in the test process: RSA 2048 and 1024, EC P-256 and
 * P-384, one on a curve the package refuses, one valid for a single day, and
 * any number of distinct P-256 ones; and a private key PEM. Each is generated
 * once per process and kept, since RSA generation is slow.
 *
 * Every certificate is self-signed for its common name, read through a minimal
 * configuration of its own, so the system's `openssl.cnf` neither shapes it nor
 * needs to exist. An Ed25519 certificate, which PHP 8.3 cannot generate, is a
 * fixed PEM: its key was thrown away when it was made.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Certificates
{
    /** @var string An Ed25519 certificate, valid from 2026-11-01 for ten years, whose key no longer exists. */
    public const string ED25519 = <<<'EOD'
        -----BEGIN CERTIFICATE-----
        MIIBJzCB2qADAgECAhRZMHeez71Nl2t7IhT4i2iuNUPKnzAFBgMrZXAwGjEYMBYG
        A1UEAwwPZWQyNTUxOS5leGFtcGxlMB4XDTI2MTEwMTA3NDAxNVoXDTM2MTAyOTA3
        NDAxNVowGjEYMBYGA1UEAwwPZWQyNTUxOS5leGFtcGxlMCowBQYDK2VwAyEAIY78
        GowWIBCe2uCd6jVoSyF/TkAKOw1rBXiplCCaRcmjMjAwMB0GA1UdDgQWBBSpS40C
        8I8OlnVNI86/bJFP6xXsbDAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANBAGwDZvOW
        Q/xSlrfW9h4ZMyaPqjsljbcPaKS0n+141bJ+cybQ9rwkIeitvx7VAsmrPQLkXmgu
        f9b/mjU+UB/vWw0=
        -----END CERTIFICATE-----
        EOD;

    /** @var array<string, array{certificate: string, private_key: string}> The certificates generated so far, by name. */
    private static array $generated = [];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * An RSA 2048 certificate, valid for a year.
     *
     * @return string
     */
    public static function rsa2048(): string
    {
        return self::generate('rsa2048', ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048], 365)['certificate'];
    }

    /**
     * An RSA 1024 certificate, weaker than the package accepts.
     *
     * @return string
     */
    public static function rsa1024(): string
    {
        return self::generate('rsa1024', ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 1024], 365)['certificate'];
    }

    /**
     * An EC P-256 certificate, valid for a year.
     *
     * @return string
     */
    public static function ecP256(): string
    {
        return self::generate('p256-0', ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'], 365)['certificate'];
    }

    /**
     * An EC P-384 certificate, valid for a year.
     *
     * @return string
     */
    public static function ecP384(): string
    {
        return self::generate('p384', ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1'], 365)['certificate'];
    }

    /**
     * An EC certificate on secp256k1, a curve the package does not accept.
     *
     * @return string
     */
    public static function unsupportedCurve(): string
    {
        return self::generate('secp256k1', ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp256k1'], 365)['certificate'];
    }

    /**
     * An EC P-256 certificate valid for one day from when it was generated.
     *
     * @return string
     */
    public static function oneDay(): string
    {
        return self::generate('one-day', ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'], 1)['certificate'];
    }

    /**
     * The RSA 2048 certificate of the index, distinct from every other index's,
     * as a SAML connection trusts one.
     *
     * @param  int  $index
     * @return string
     */
    public static function distinct(int $index): string
    {
        return self::generate('rsa-' . $index, ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048], 365)['certificate'];
    }

    /**
     * An RSA 2048 certificate valid for one day from when it was generated.
     *
     * @return string
     */
    public static function rsaOneDay(): string
    {
        return self::generate('rsa-one-day', ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048], 1)['certificate'];
    }

    /**
     * The private key of the EC P-256 certificate, PEM-encoded.
     *
     * @return string
     */
    public static function privateKey(): string
    {
        self::ecP256();

        return self::$generated['p256-0']['private_key'];
    }

    /**
     * The certificate and private key of the name, generated on first use.
     *
     * @param  string  $name
     * @param  array<string, int|string>  $options
     * @param  int  $days
     * @return array{certificate: string, private_key: string}
     */
    private static function generate(string $name, array $options, int $days): array
    {
        if (isset(self::$generated[$name])) {
            return self::$generated[$name];
        }

        $config      = (string) tempnam(sys_get_temp_dir(), 'sso-test-openssl-');
        $certificate = '';
        $privateKey  = '';

        // PHP 8.3 checks default_bits against RSA's minimum even for an EC key.
        file_put_contents($config, "[req]\ndefault_bits = 2048\ndistinguished_name = subject\n\n[subject]\n");

        try {
            $options += ['config' => $config, 'digest_alg' => 'sha256'];
            $key = openssl_pkey_new($options);

            assert($key !== false);

            $request = openssl_csr_new(['commonName' => $name . '.idp.example'], $key, $options);

            assert($request instanceof \OpenSSLCertificateSigningRequest);

            $signed = openssl_csr_sign($request, null, $key, $days, $options, 1 + crc32($name));

            assert($signed !== false);

            openssl_x509_export($signed, $certificate);
            openssl_pkey_export($key, $privateKey, null, $options);
        } finally {
            unlink($config);

            do {
                $error = openssl_error_string();
            } while ($error !== false);
        }

        return self::$generated[$name] = ['certificate' => $certificate, 'private_key' => $privateKey];
    }
}
