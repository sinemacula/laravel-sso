<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Freshness;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\Freshness;

/**
 * The example application's service provider, binding its freshness contract.
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
