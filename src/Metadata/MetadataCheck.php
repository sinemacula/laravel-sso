<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * `[metadata]`: how large metadata may be, while the `saml2` feature is on, and
 * how the scheduled metadata refresh runs and is queued, while the
 * `metadata_refresh` feature is on too (SSO-2.8, SSO-12.3), each setting read
 * as `MetadataSettings` reads it, so the check, the import and the refresh
 * judge it the same way.
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
     * The settings are checked while the package is in use, since the stale
     * limit and an administrator's refresh do not depend on the schedule.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse();
    }

    /**
     * The size cap, the interval, the backoff, the stale limit and the claim,
     * then, while the schedule is on, the queue its refreshes are sent to.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $settings = new MetadataSettings($this->config);
        $always   = [
            static fn (): int => $settings->maxBytes(),
            static fn (): int => $settings->refreshIntervalSeconds(),
            static fn (): int => $settings->backoffInitialSeconds(),
            static fn (): int => $settings->backoffMaxSeconds(),
            static fn (): ?int => $settings->staleLimitSeconds(),
            static fn (): int => $settings->claimSeconds(),
        ];

        if (!Features::requested(Feature::METADATA_REFRESH)) {
            return $always;
        }

        return [
            ...$always,
            static fn (): ?string => $settings->queueConnection(),
            static fn (): ?string => $settings->queueName(),
            static fn (): int => $settings->timeoutSeconds(),
            static fn (): int => $settings->tries(),
        ];
    }
}
