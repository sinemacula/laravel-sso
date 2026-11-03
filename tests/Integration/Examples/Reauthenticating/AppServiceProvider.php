<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Reauthenticating;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;

/**
 * The example application's service provider (SSO-5.10, SSO-9.5): it binds the
 * application's own re-authentication contract in place of the package's
 * default, which answers that no identity is signed in on any session. It
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
