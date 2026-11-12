<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\BooleanSetting;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;
use SineMacula\Laravel\Sso\Links\LinkStorageBinding;

/**
 * Checks `sso.linking` at boot, while the package is in use.
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
     * @param  \SineMacula\Laravel\Sso\Links\LinkStorageBinding  $storage
     */
    public function __construct(

        /** The configuration checked. */
        private Repository $config,

        /** Whether the bound linker is backed by link storage. */
        private LinkStorageBinding $storage,
    ) {}

    /**
     * Linking's settings are checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse($this->config);
    }

    /**
     * Read each linking setting, and check the linker's storage.
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
            $this->assertStorage(...),
        ];
    }

    /**
     * Refuse linking by a verified domain over a linker that is not backed by
     * link storage.
     *
     * @return void
     *
     * @throws \LogicException
     * @throws \InvalidArgumentException
     */
    private function assertStorage(): void
    {
        $feature = Feature::DOMAIN_LINKING;

        if (!BooleanSetting::isOn($feature->key(), $this->config->get($feature->key(), $feature->isOnByDefault()))) {
            return;
        }

        $this->storage->require('The `domain_linking` feature');
    }
}
