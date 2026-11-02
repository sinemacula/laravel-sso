<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * Checks `sso.linking` at boot, while the package is in use (SSO-12.3).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LinkingCheck implements ConfigurationCheck
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
     * Linking's settings are checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse();
    }

    /**
     * The verified response's validity, the evidence's maximum age and the
     * shared issuers.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $settings = new LinkingSettings($this->config);

        return [
            $settings->verifiedResultMaxAgeSeconds(...),
            $settings->evidenceMaxAgeSeconds(...),
            $settings->sharedIssuers(...),
        ];
    }
}
