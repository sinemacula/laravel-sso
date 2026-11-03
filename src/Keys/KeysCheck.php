<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * `[keys]`: the settings of the keys the package generates and rotates, while
 * the package is in use (SSO-2.7), each read as `KeySettings` reads it, so the
 * check and the key operations judge it the same way. The table's name is
 * checked under `[storage]`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class KeysCheck implements ConfigurationCheck
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration checked. */
        private Repository $config,
    ) {}

    /**
     * Keys are checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse();
    }

    /**
     * The RSA modulus, the certificate validity, the overlap, the expiry
     * thresholds and how long a reporter holds a key.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $settings = new KeySettings($this->config);

        return [
            static fn (): int => $settings->rsaBits(),
            static fn (): int => $settings->certificateDays(),
            static fn (): int => $settings->overlapSeconds(),
            static fn (): ExpiryThresholds => $settings->expiryThresholds(),
            static fn (): int => $settings->expiryClaimSeconds(),
        ];
    }
}
