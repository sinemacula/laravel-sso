<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\OutboundRequests;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\Fetcher;

/**
 * The service provider of an application whose outbound traffic must leave
 * through an egress proxy (SSO-2.9): it binds the application's own fetcher in
 * place of the package's, which never uses a proxy. It registers after the
 * package's provider, as an application's providers do, so its binding replaces
 * the default as any later binding does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EgressProxyServiceProvider extends ServiceProvider
{
    /**
     * Bind the application's fetcher.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        // @snippet-start outbound-proxied-fetcher
        // One fetcher per request or job, as the package's own is bound
        $this->app->scoped(Fetcher::class, ProxiedFetcher::class);
        // @snippet-end outbound-proxied-fetcher
    }
}
