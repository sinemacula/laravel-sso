<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Reauthenticating;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;

/**
 * The example application's service provider: binds its sessions over the
 * package's default, which finds nobody signed in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AppServiceProvider extends ServiceProvider
{
    /**
     * Bind the application's sessions.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        // @snippet-start reauthenticating-binding
        $this->app->bind(ReauthenticationSessions::class, UserSessions::class);
        // @snippet-end reauthenticating-binding
    }
}
