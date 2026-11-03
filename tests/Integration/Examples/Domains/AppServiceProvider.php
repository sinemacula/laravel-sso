<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Domains;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;

/**
 * The example application's service provider (SSO-3.2): it binds the
 * application's own DNS resolver in place of the package's default. It
 * registers after the package's provider, as an application's providers do, so
 * its binding replaces the default as any later binding does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AppServiceProvider extends ServiceProvider
{
    /**
     * Bind the application's DNS resolver.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        // @snippet-start dns-resolver
        $this->app->scoped(DnsResolver::class, DohResolver::class);
        // @snippet-end dns-resolver
    }
}
