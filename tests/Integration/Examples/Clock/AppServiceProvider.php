<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Clock;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;

/**
 * The example application's service provider (SSO-11.13): it binds the
 * application's own clock in place of the package's default. It registers after
 * the package's provider, as an application's providers do, so its binding
 * replaces the default as any later binding does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AppServiceProvider extends ServiceProvider
{
    /**
     * Bind the application's clock.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        // @snippet-start own-clock
        // One clock for every request and job: it holds no instant between them
        $this->app->singleton(Clock::class, UtcClock::class);
        // @snippet-end own-clock
    }
}
