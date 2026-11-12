<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config\Checks;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;
use SineMacula\Laravel\Sso\Endpoints\EndpointSettings;
use SineMacula\Laravel\Sso\Endpoints\Enums\Endpoint;

/**
 * Checks the settings the default endpoint resolver builds URLs from, so a bad
 * one fails at boot rather than on the first sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EndpointsCheck implements ConfigurationCheck
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
     * Applies while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse($this->config);
    }

    /**
     * The base URL, each path pattern, then that the patterns are distinct.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $settings = new EndpointSettings($this->config);
        $checks   = [static fn (): string => $settings->baseUrl()];

        foreach (Endpoint::cases() as $endpoint) {
            $checks[] = static fn (): string => $settings->pattern($endpoint);
        }

        $checks[] = static function () use ($settings): void {
            $settings->assertDistinct();
        };

        return $checks;
    }
}
