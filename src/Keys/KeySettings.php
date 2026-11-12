<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The `sso.keys` settings, read on each call; a malformed one fails closed
 * naming its key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class KeySettings
{
    /** @var string The curve of every generated EC key: P-256, by OpenSSL's name. */
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

    /** @var list<int> The days before an end of validity a key is warned of when none are configured. */
    public const array DEFAULT_EXPIRY_THRESHOLDS = [30, 14, 7, 1, 0];

    /** @var int The most days before an end of validity a key may be warned of. */
    public const int MAX_EXPIRY_THRESHOLD = 365;

    /** @var int How long a reporter holds a key when none is configured, in seconds. */
    public const int DEFAULT_EXPIRY_CLAIM_SECONDS = 300;

    /** @var int The longest a reporter may hold a key, in seconds. */
    public const int MAX_EXPIRY_CLAIM_SECONDS = 3600;

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
     * The days before an end of validity a key or certificate is warned of.
     *
     * @return \SineMacula\Laravel\Sso\Keys\ExpiryThresholds
     *
     * @throws \InvalidArgumentException
     */
    public function expiryThresholds(): ExpiryThresholds
    {
        return ExpiryThresholds::parse($this->config->get('sso.keys.expiry_thresholds', self::DEFAULT_EXPIRY_THRESHOLDS));
    }

    /**
     * How long one reporter holds a key while it sends a warning, in seconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function expiryClaimSeconds(): int
    {
        return IntegerSetting::read($this->config, 'sso.keys.expiry_claim_seconds', self::DEFAULT_EXPIRY_CLAIM_SECONDS, 1, self::MAX_EXPIRY_CLAIM_SECONDS);
    }
}
