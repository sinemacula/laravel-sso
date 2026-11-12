<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * `[domains]`: the domain settings, read through `DomainSettings` so the check
 * judges them as the domain operations do.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DomainsCheck implements ConfigurationCheck
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
     * Domains are checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse($this->config);
    }

    /**
     * Read each domain setting.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $settings = new DomainSettings($this->config);

        return [
            static fn (): string => $settings->recordName(),
            static fn (): array => $settings->refused(),
            static fn (): int => $settings->pendingExpirySeconds(),
            static fn (): int => $settings->recheckGraceSeconds(),
            static fn (): int => $settings->linkingMaxAgeSeconds(),
        ];
    }
}
