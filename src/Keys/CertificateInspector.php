<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;

/**
 * Reads and judges an identity provider certificate before it is trusted.
 *
 * Its dates are reported, never judged: an expired certificate is accepted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-type CertificateFacts array{
 *     certificate: string,
 *     public_key: string,
 *     fingerprint: string,
 *     type: \SineMacula\Laravel\Sso\Keys\Enums\KeyType,
 *     bits: int,
 *     not_before: \Carbon\CarbonImmutable,
 *     not_after: \Carbon\CarbonImmutable
 * }
 *
 * @internal
 */
final readonly class CertificateInspector
{
    /** @var int The longest certificate PEM accepted, in bytes. */
    public const int MAX_LENGTH = 16384;

    /** @var int The smallest RSA modulus accepted, in bits. */
    public const int MIN_RSA_BITS = 2048;

    /** @var list<string> The elliptic curves accepted, by OpenSSL's names: P-256, P-384 and P-521. */
    public const array CURVES = ['prime256v1', 'secp384r1', 'secp521r1'];

    /** @var string The setting every violation names. */
    public const string SETTING = 'certificate';

    /**
     * The certificate's facts or why it is refused, never both.
     *
     * @param  string  $pem
     * @return array{facts: ?CertificateFacts, violations: list<\SineMacula\Laravel\Sso\Connections\SettingViolation>}
     */
    public function inspect(string $pem): array
    {
        $code = match (true) {
            strlen($pem) > self::MAX_LENGTH   => ViolationCode::TOO_LONG,
            str_contains($pem, 'PRIVATE KEY') => ViolationCode::PRIVATE_KEY_REFUSED,
            default                           => null,
        };

        $read = $code ?? self::read($pem);

        return $read instanceof ViolationCode ? self::refused($read) : ['facts' => $read, 'violations' => []];
    }

    /**
     * The facts of a PEM that holds no private key, or why it is refused.
     *
     * @param  string  $pem
     * @return CertificateFacts|\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private static function read(string $pem): array|ViolationCode
    {
        $masked   = self::masked($pem);
        $details  = $masked === null ? false : self::quietly(static fn (): array|false => self::details($masked['public_key']));
        $validity = $masked === null ? null : self::validity($masked['certificate']);

        if ($masked === null || $details === false || $validity === null) {
            return ViolationCode::INVALID_FORMAT;
        }

        $type = self::type($details);

        return match (true) {
            $type === null                   => ViolationCode::NOT_ALLOWED,
            !self::isStrong($type, $details) => ViolationCode::WEAK_KEY,
            default                          => [
                'certificate' => $masked['certificate'],
                'public_key'  => $masked['public_key'],
                'fingerprint' => $masked['fingerprint'],
                'type'        => $type,
                'bits'        => $details['bits'],
                'not_before'  => $validity[0],
                'not_after'   => $validity[1],
            ],
        };
    }

    /**
     * The canonical PEM, public key and fingerprint of exactly one X.509
     * certificate, or `null` for anything else.
     *
     * @param  string  $pem
     * @return ?array{certificate: string, public_key: string, fingerprint: string}
     */
    private static function masked(string $pem): ?array
    {
        try {
            $masked = MaskedKey::fromCertificate($pem);
        } catch (\InvalidArgumentException) {
            return null;
        }

        return $masked->certificate === null || $masked->publicKey === null || $masked->fingerprint === null
            ? null
            : ['certificate' => $masked->certificate, 'public_key' => $masked->publicKey, 'fingerprint' => $masked->fingerprint];
    }

    /**
     * The certificate refused for the reason given.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\Enums\ViolationCode  $code
     * @return array{facts: null, violations: list<\SineMacula\Laravel\Sso\Connections\SettingViolation>}
     */
    private static function refused(ViolationCode $code): array
    {
        return ['facts' => null, 'violations' => [new SettingViolation(self::SETTING, $code)]];
    }

    /**
     * The public key's type, size and curve, or `false` when OpenSSL cannot
     * read them.
     *
     * @param  string  $publicKey
     * @return array{type: int, bits: int, curve: ?string}|false
     */
    private static function details(string $publicKey): array|false
    {
        $key     = openssl_pkey_get_public($publicKey);
        $details = $key === false ? false : openssl_pkey_get_details($key);

        if ($details === false || !is_int($details['type'] ?? null) || !is_int($details['bits'] ?? null)) {
            return false;
        }

        $curve = $details['ec']['curve_name'] ?? null;

        return ['type' => $details['type'], 'bits' => $details['bits'], 'curve' => is_string($curve) ? $curve : null];
    }

    /**
     * The kind of key, or `null` for a kind the package does not accept.
     *
     * @param  array{type: int, bits: int, curve: ?string}  $details
     * @return ?\SineMacula\Laravel\Sso\Keys\Enums\KeyType
     */
    private static function type(array $details): ?KeyType
    {
        return match ($details['type']) {
            OPENSSL_KEYTYPE_RSA => KeyType::RSA,
            OPENSSL_KEYTYPE_EC  => KeyType::EC,
            default             => null,
        };
    }

    /**
     * Whether the RSA modulus is long enough or the curve is accepted.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  array{type: int, bits: int, curve: ?string}  $details
     * @return bool
     */
    private static function isStrong(KeyType $type, array $details): bool
    {
        return match ($type) {
            KeyType::RSA => $details['bits'] >= self::MIN_RSA_BITS,
            KeyType::EC  => in_array($details['curve'], self::CURVES, true),
        };
    }

    /**
     * When the certificate's validity starts and ends, in UTC, or `null` when
     * OpenSSL cannot read them.
     *
     * @param  string  $certificate
     * @return ?array{0: \Carbon\CarbonImmutable, 1: \Carbon\CarbonImmutable}
     */
    private static function validity(string $certificate): ?array
    {
        $parsed = self::quietly(static fn (): array|false => openssl_x509_parse($certificate));
        $from   = $parsed === false ? null : ($parsed['validFrom_time_t'] ?? null);
        $to     = $parsed === false ? null : ($parsed['validTo_time_t'] ?? null);

        if (!is_int($from) || !is_int($to)) {
            return null;
        }

        return [CarbonImmutable::createFromTimestamp($from, 'UTC'), CarbonImmutable::createFromTimestamp($to, 'UTC')];
    }

    /**
     * Run an OpenSSL read with its warnings silenced and its error queue
     * cleared, so neither reaches a log or a later call.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $read
     * @return TResult
     */
    private static function quietly(\Closure $read): mixed
    {
        set_error_handler(static fn (): bool => true);

        try {
            return $read();
        } finally {
            restore_error_handler();

            do {
                $error = openssl_error_string();
            } while ($error !== false);
        }
    }
}
