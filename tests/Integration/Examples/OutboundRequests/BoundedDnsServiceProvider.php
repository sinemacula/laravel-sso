<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\OutboundRequests;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\HostResolver;

/**
 * Binds a host resolver with a bounded lookup, since PHP cannot interrupt the
 * system resolver.
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
