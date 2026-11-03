<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\OutboundRequests;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\HostResolver;

/**
 * The service provider of an application whose system resolver can be slow
 * (SSO-2.9): it keeps the package's fetcher and binds a host resolver whose
 * lookup is bounded in place of the package's, which PHP cannot interrupt. It
 * registers after the package's provider, as an application's providers do, so
 * its binding replaces the default as any later binding does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BoundedDnsServiceProvider extends ServiceProvider
{
    /**
     * Bind the application's host resolver.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        // @snippet-start outbound-host-resolver
        // One resolver for every request and job: it keeps no state
        $this->app->singleton(HostResolver::class, BoundedHostResolver::class);
        // @snippet-end outbound-host-resolver
    }
}
