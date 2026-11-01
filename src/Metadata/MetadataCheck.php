<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * `[metadata]`: how the scheduled metadata refresh runs, while the
 * `metadata_refresh` feature is on (SSO-2.8, SSO-12.3), each setting read as
 * `MetadataSettings` reads it, so the check and the refresh judge it the same
 * way.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MetadataCheck implements ConfigurationCheck
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
     * The settings are checked while the `metadata_refresh` feature is on, or
     * its switch is malformed.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::requested(Feature::METADATA_REFRESH);
    }

    /**
     * The interval, the backoff, the stale limit and the claim.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $settings = new MetadataSettings($this->config);

        return [
            static fn (): int => $settings->refreshIntervalSeconds(),
            static fn (): int => $settings->backoffInitialSeconds(),
            static fn (): int => $settings->backoffMaxSeconds(),
            static fn (): ?int => $settings->staleLimitSeconds(),
            static fn (): int => $settings->claimSeconds(),
        ];
    }
}
