<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The settings of the keys the package generates and rotates (SSO-2.6,
 * SSO-2.7), read from `sso.keys` on each call (SSO-11.2), each failing closed
 * with an `InvalidArgumentException` naming its key when it is malformed;
 * `[keys]` reports the same at boot.
 *
 * - `rsa_bits`: the modulus of a generated RSA key, 3072 (default) or 4096.
 *   Elliptic curve keys are always generated on P-256 (`EC_CURVE`).
 * - `certificate_days`: how long a generated self-signed certificate is valid
 *   for, 1 to 3650 days (default 730). Its dates are reported, never enforced.
 * - `overlap_seconds`: how long a key replaced as current is kept `retiring`,
 *   accepted for decryption, 0 to 7776000 seconds (90 days; default 604800, a
 *   week).
 * - `expiry_warning_days`: how far ahead a certificate's expiry is reported as
 *   near, 1 to 365 days (default 30).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class KeySettings
{
    /** @var string The elliptic curve every generated elliptic curve key is on: P-256, by OpenSSL's name. */
    public const string EC_CURVE = 'prime256v1';

    /** @var list<int> The RSA moduli a generated key may have, in bits. */
    public const array RSA_BITS = [3072, 4096];

    /** @var int The RSA modulus generated when none is configured, in bits. */
    public const int DEFAULT_RSA_BITS = 3072;

    /** @var int A generated certificate's validity when none is configured, in days. */
    public const int DEFAULT_CERTIFICATE_DAYS = 730;

    /** @var int The overlap when none is configured, in seconds (a week). */
    public const int DEFAULT_OVERLAP_SECONDS = 604800;

    /** @var int The greatest overlap that may be configured, in seconds (90 days). */
    public const int MAX_OVERLAP_SECONDS = 7776000;

    /** @var int How far ahead an expiry is reported when none is configured, in days. */
    public const int DEFAULT_EXPIRY_WARNING_DAYS = 30;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the settings are read from. */
        private Repository $config,
    ) {}

    /**
     * The modulus of a generated RSA key, in bits.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function rsaBits(): int
    {
        $bits = IntegerSetting::parse($this->config->get('sso.keys.rsa_bits', self::DEFAULT_RSA_BITS));

        if (!in_array($bits, self::RSA_BITS, true)) {
            throw new \InvalidArgumentException(sprintf('sso.keys.rsa_bits must be one of %s.', implode(', ', self::RSA_BITS)));
        }

        return $bits;
    }

    /**
     * How long a generated certificate is valid for, in days.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function certificateDays(): int
    {
        return IntegerSetting::read($this->config, 'sso.keys.certificate_days', self::DEFAULT_CERTIFICATE_DAYS, 1, 3650);
    }

    /**
     * How long a replaced key stays `retiring`, in seconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function overlapSeconds(): int
    {
        return IntegerSetting::read($this->config, 'sso.keys.overlap_seconds', self::DEFAULT_OVERLAP_SECONDS, 0, self::MAX_OVERLAP_SECONDS);
    }

    /**
     * How far ahead a certificate's expiry is reported as near, in days.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function expiryWarningDays(): int
    {
        return IntegerSetting::read($this->config, 'sso.keys.expiry_warning_days', self::DEFAULT_EXPIRY_WARNING_DAYS, 1, 365);
    }
}
