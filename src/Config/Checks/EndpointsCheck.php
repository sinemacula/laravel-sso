<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config\Checks;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;
use SineMacula\Laravel\Sso\Endpoints\EndpointSettings;
use SineMacula\Laravel\Sso\Endpoints\Enums\Endpoint;

/**
 * `[endpoints]`: what the default endpoint resolver builds the package's URLs
 * from (SSO-5.5), while the package is in use, so a resolver that cannot build
 * them fails at boot rather than on the first sign-in (SSO-12.3).
 *
 * Each setting is read by `Endpoints\EndpointSettings`, the one way the default
 * resolver reads it too: `sso.endpoints.base_url` is a web URL with no query
 * (see `UrlSetting::web()`), and each pattern in `sso.endpoints.paths` an
 * absolute path holding `{connection}` once, with no query, fragment, wildcard
 * or dot segment, and distinct from the others. Nothing is ever built from the
 * request's host or headers. An application that binds a resolver of its own
 * still names these, since the default's settings are what this checks.
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
     * The endpoints are checked while the package is in use.
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
