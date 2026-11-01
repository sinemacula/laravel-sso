<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use Carbon\CarbonImmutable;
use Random\RandomException;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * Generates the service provider's own key pairs, each with a self-signed
 * certificate (SSO-2.7), with PHP's OpenSSL extension alone, so the keys do not
 * depend on the SAML or JOSE library that later signs or decrypts with them.
 *
 * An RSA key has the modulus `sso.keys.rsa_bits` gives (3072 by default); an
 * elliptic curve key is on P-256 (`KeySettings::EC_CURVE`). The certificate
 * names the common name it is given (the connection's id), is signed with
 * SHA-256 by the key itself, has a random positive serial number, and is valid
 * from the moment it is signed for `sso.keys.certificate_days`.
 *
 * Every option is passed to OpenSSL explicitly, and the package ships no
 * `openssl.cnf`. OpenSSL builds a certificate request only from a configuration
 * file, and the system's would add its default subject fields (a country, an
 * organisation) and its own extensions, or be missing; so each call writes a
 * minimal configuration (`CONFIGURATION`: no default subject field, and only
 * `basicConstraints = critical,CA:FALSE`) to a temporary file of its own, uses
 * it for every OpenSSL step, and removes it, whatever happens.
 *
 * OpenSSL's warnings are silenced and its error queue cleared after each call,
 * so nothing of a key reaches a log or a later call. A step that fails throws a
 * `RuntimeException` naming the step, never the key. It never logs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KeyGenerator
{
    /** @var string The digest every certificate is signed with. */
    public const string DIGEST = 'sha256';

    /** @var int The longest common name a certificate may name (X.520's upper bound), in bytes. */
    public const int MAX_COMMON_NAME_LENGTH = 64;

    /** @var string The step that reads a generated certificate back. */
    private const string CERTIFICATE_READ = 'certificate read';

    /** @var string The section of `CONFIGURATION` that holds the certificate's extensions. */
    private const string EXTENSIONS = 'sso_certificate';

    /** @var string The configuration every OpenSSL step reads: no default subject field, and a certificate that is not a certificate authority's. */
    private const string CONFIGURATION = "[req]\ndistinguished_name = sso_subject\n\n[sso_subject]\n\n[sso_certificate]\nbasicConstraints = critical,CA:FALSE\n";

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeySettings  $settings
     */
    public function __construct(

        /** The RSA modulus and the certificate's validity, read on each call. */
        private KeySettings $settings,
    ) {}

    /**
     * A new key pair of the type, with a self-signed certificate naming the
     * common name.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  string  $commonName
     * @return \SineMacula\Laravel\Sso\Keys\GeneratedKey
     *
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    public function generate(KeyType $type, string $commonName): GeneratedKey
    {
        self::assertCommonName($commonName);

        $days    = $this->settings->certificateDays();
        $options = $this->keyOptions($type);
        $config  = self::configuration();

        try {
            return self::generateWith($config, $type, $options, $commonName, $days);
        } finally {
            self::quietly(static fn (): bool => unlink($config));
        }
    }

    /**
     * Refuse a common name a certificate cannot name.
     *
     * @param  string  $commonName
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertCommonName(string $commonName): void
    {
        if ($commonName === '' || strlen($commonName) > self::MAX_COMMON_NAME_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A certificate\'s common name is 1 to %d bytes.', self::MAX_COMMON_NAME_LENGTH));
        }
    }

    /**
     * The key pair and its certificate, generated with the configuration file
     * given.
     *
     * @param  string  $config
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  array<string, int|string>  $options
     * @param  string  $commonName
     * @param  int  $days
     * @return \SineMacula\Laravel\Sso\Keys\GeneratedKey
     *
     * @throws \RuntimeException
     */
    private static function generateWith(string $config, KeyType $type, array $options, string $commonName, int $days): GeneratedKey
    {
        $options += ['config' => $config];
        $key = self::quietly(static fn (): false|\OpenSSLAsymmetricKey => openssl_pkey_new($options));

        if ($key === false) {
            throw self::failure('key generation');
        }

        $certificate = self::certificate($key, $commonName, $days, $config);
        $privateKey  = self::privateKey($key, $config);
        $masked      = self::masked($certificate);
        $bits        = self::bits($key);
        $validity    = self::validity($certificate);

        return new GeneratedKey(
            privateKey: $privateKey,
            publicKey: $masked['public_key'],
            certificate: $masked['certificate'],
            type: $type,
            bits: $bits,
            notBefore: $validity[0],
            notAfter: $validity[1],
            fingerprint: $masked['fingerprint'],
        );
    }

    /**
     * Write `CONFIGURATION` to a temporary file of its own, and answer its
     * path.
     *
     * @return string
     *
     * @throws \RuntimeException
     */
    private static function configuration(): string
    {
        $path = self::quietly(static fn (): false|string => tempnam(sys_get_temp_dir(), 'sso-openssl-'));

        if ($path === false) {
            throw self::failure('configuration');
        }

        if (self::quietly(static fn (): false|int => file_put_contents($path, self::CONFIGURATION)) !== strlen(self::CONFIGURATION)) {
            self::quietly(static fn (): bool => unlink($path));

            throw self::failure('configuration');
        }

        return $path;
    }

    /**
     * The options OpenSSL generates a key of the type with: the configured RSA
     * modulus, or P-256.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @return array<string, int|string>
     *
     * @throws \InvalidArgumentException
     */
    private function keyOptions(KeyType $type): array
    {
        return match ($type) {
            KeyType::RSA => ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $this->settings->rsaBits(), 'digest_alg' => self::DIGEST],
            KeyType::EC  => ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => KeySettings::EC_CURVE, 'digest_alg' => self::DIGEST],
        };
    }

    /**
     * The key's self-signed certificate, PEM-encoded: the common name as its
     * subject and issuer, SHA-256, a random positive serial number, valid for
     * the days given.
     *
     * @param  \OpenSSLAsymmetricKey  $key
     * @param  string  $commonName
     * @param  int  $days
     * @param  string  $config
     * @return string
     *
     * @throws \RuntimeException
     */
    private static function certificate(\OpenSSLAsymmetricKey $key, string $commonName, int $days, string $config): string
    {
        $options = ['config' => $config, 'digest_alg' => self::DIGEST, 'x509_extensions' => self::EXTENSIONS];
        $request = self::quietly(static fn (): bool|\OpenSSLCertificateSigningRequest => openssl_csr_new(['commonName' => $commonName], $key, $options));

        if (!$request instanceof \OpenSSLCertificateSigningRequest) {
            throw self::failure('certificate request');
        }

        $serial = self::serial();
        $signed = self::quietly(static fn (): false|\OpenSSLCertificate => openssl_csr_sign($request, null, $key, $days, $options, $serial));

        if ($signed === false) {
            throw self::failure('certificate signing');
        }

        $pem = self::quietly(static fn (): ?string => openssl_x509_export($signed, $exported) ? $exported : null);

        if ($pem === null || $pem === '') {
            throw self::failure('certificate export');
        }

        return $pem;
    }

    /**
     * A random positive serial number for a certificate.
     *
     * @return int
     *
     * @throws \RuntimeException
     */
    private static function serial(): int
    {
        try {
            return random_int(1, PHP_INT_MAX);
        } catch (RandomException) {
            throw self::failure('serial number');
        }
    }

    /**
     * The key's private half, PEM-encoded and unencrypted, as a secret.
     *
     * @param  \OpenSSLAsymmetricKey  $key
     * @param  string  $config
     * @return \SineMacula\Laravel\Sso\Secrets\Secret
     *
     * @throws \RuntimeException
     */
    private static function privateKey(\OpenSSLAsymmetricKey $key, string $config): Secret
    {
        $pem = self::quietly(static fn (): ?string => openssl_pkey_export($key, $exported, null, ['config' => $config, 'encrypt_key' => false]) ? $exported : null);

        if ($pem === null || $pem === '') {
            throw self::failure('private key export');
        }

        return new Secret($pem);
    }

    /**
     * The certificate's canonical PEM, its public key and its fingerprint, as
     * `Secrets\MaskedKey` reads them.
     *
     * @param  string  $certificate
     * @return array{certificate: string, public_key: string, fingerprint: string}
     *
     * @throws \RuntimeException
     */
    private static function masked(string $certificate): array
    {
        try {
            $masked = MaskedKey::fromCertificate($certificate);
        } catch (\InvalidArgumentException) {
            throw self::failure(self::CERTIFICATE_READ);
        }

        if ($masked->certificate === null || $masked->publicKey === null || $masked->fingerprint === null) {
            throw self::failure(self::CERTIFICATE_READ);
        }

        return ['certificate' => $masked->certificate, 'public_key' => $masked->publicKey, 'fingerprint' => $masked->fingerprint];
    }

    /**
     * The key's size: the RSA modulus, or the elliptic curve's, in bits.
     *
     * @param  \OpenSSLAsymmetricKey  $key
     * @return int
     *
     * @throws \RuntimeException
     */
    private static function bits(\OpenSSLAsymmetricKey $key): int
    {
        $details = self::quietly(static fn (): array|false => openssl_pkey_get_details($key));
        $bits    = $details === false ? null : ($details['bits'] ?? null);

        if (!is_int($bits)) {
            throw self::failure('key read');
        }

        return $bits;
    }

    /**
     * When the certificate's validity starts and ends, in UTC.
     *
     * @param  string  $certificate
     * @return array{0: \Carbon\CarbonImmutable, 1: \Carbon\CarbonImmutable}
     *
     * @throws \RuntimeException
     */
    private static function validity(string $certificate): array
    {
        $parsed = self::quietly(static fn (): array|false => openssl_x509_parse($certificate));
        $from   = $parsed === false ? null : ($parsed['validFrom_time_t'] ?? null);
        $to     = $parsed === false ? null : ($parsed['validTo_time_t'] ?? null);

        if (!is_int($from) || !is_int($to)) {
            throw self::failure(self::CERTIFICATE_READ);
        }

        return [CarbonImmutable::createFromTimestamp($from, 'UTC'), CarbonImmutable::createFromTimestamp($to, 'UTC')];
    }

    /**
     * The failure of the step, naming the step only.
     *
     * @param  string  $step
     * @return \RuntimeException
     */
    private static function failure(string $step): \RuntimeException
    {
        return new \RuntimeException(sprintf('OpenSSL could not complete the %s.', $step));
    }

    /**
     * Run an OpenSSL call with its warnings silenced (its result says whether
     * it failed) and its error queue cleared, so neither reaches a log or a
     * later call.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $call
     * @return TResult
     */
    private static function quietly(\Closure $call): mixed
    {
        set_error_handler(static fn (): bool => true);

        try {
            return $call();
        } finally {
            restore_error_handler();

            do {
                $error = openssl_error_string();
            } while ($error !== false);
        }
    }
}
