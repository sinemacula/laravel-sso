<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Freshness;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\Freshness;

/**
 * The example application's service provider (SSO-2.12): it binds the
 * application's own freshness contract in place of the package's default, which
 * refuses every operation, and the record of sign-ins it reads. It registers
 * after the package's provider, as an application's providers do, so its
 * binding replaces the default as any later binding does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AppServiceProvider extends ServiceProvider
{
    /**
     * Bind the application's freshness contract and its record of sign-ins.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->app->singleton(SignInTimes::class);
        // @snippet-start freshness-binding
        $this->app->singleton(Freshness::class, RecentSignInFreshness::class);
        // @snippet-end freshness-binding
    }
}
