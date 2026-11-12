<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\OutboundRequests;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\Fetcher;

/**
 * Binds a fetcher that sends through an egress proxy, which the package's
 * fetcher never uses.
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
