<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Domains;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;

/**
 * Binds the application's DNS resolver in place of the package's default.
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
