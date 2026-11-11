<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Configuration;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * The example application's own configuration check, added to the package's
 * (SSO-12.3): while the package is in use, every client's host must be set,
 * since the application's redirect URI resolver sends the web application to
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ClientHostsCheck implements ConfigurationCheck
{
    // @snippet-start configuration-added-check
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
     * Whether the package is in use, so an application with it off never fails
     * its boot on this check.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse($this->config);
    }

    /**
     * Each client's host must be a non-empty string.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        return [
            function (): void {
                $hosts = $this->config->get('clients.hosts');

                if (!is_array($hosts) || $hosts === [] || array_filter($hosts, static fn (mixed $host): bool => !is_string($host) || $host === '') !== []) {
                    throw new \InvalidArgumentException('`clients.hosts` must give each client a host.');
                }
            },
        ];
    }
    // @snippet-end configuration-added-check
}
