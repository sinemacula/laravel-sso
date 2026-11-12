<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Clock;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;

/**
 * The example application's service provider, which binds its own clock.
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
