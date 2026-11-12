<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Configuration;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Config\ConfigurationChecks;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\RedirectUriResolver;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints;

/**
 * The example application's service provider: per-connection endpoints,
 * per-client redirect hosts, and its own configuration check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AppServiceProvider extends ServiceProvider
{
    /**
     * Bind the application's endpoint and redirect URI resolvers and add its
     * host check.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        // @snippet-start configuration-endpoint-resolver
        $this->app->scoped(EndpointResolver::class, static fn (): EndpointResolver => new class implements EndpointResolver {
            /**
             * The connection's endpoints, under its own path.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints
             */
            #[\Override]
            public function endpoints(SsoConnection $connection): ConnectionEndpoints
            {
                $base = 'https://sso.example.com/' . rawurlencode($connection->getConnectionId());

                return new ConnectionEndpoints("{$base}/acs", "{$base}/callback", "{$base}/metadata", "{$base}/metadata", "{$base}/jwks");
            }
        });
        // @snippet-end configuration-endpoint-resolver
        // @snippet-start configuration-redirect-uri-resolver
        $this->app->singleton(RedirectUriResolver::class, static fn (): RedirectUriResolver => new class implements RedirectUriResolver {
            /**
             * The web application on the host of the connection's client, and
             * every other application on its registered redirect URI.
             *
             * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return string
             */
            #[\Override]
            public function redirectUri(Application $application, SsoConnection $connection): string
            {
                return $application->name === 'web'
                    ? 'https://' . ClientHosts::for($connection->getTenantId()) . '/auth/sso/complete'
                    : $application->redirectUri;
            }
        });
        // @snippet-end configuration-redirect-uri-resolver
        // @snippet-start configuration-add-check
        $this->callAfterResolving(ConfigurationChecks::class, static function (ConfigurationChecks $checks): void {
            $checks->add('clients', ClientHostsCheck::class);
        });
        // @snippet-end configuration-add-check
    }
}
