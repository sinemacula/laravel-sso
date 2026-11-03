<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\SingleUseStore;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;

/**
 * The example application's service provider (SSO-11.5): it binds the
 * application's own single-use store in place of the package's default, scoped
 * so each request or job builds its own. It registers after the package's
 * provider, as an application's providers do, so its binding replaces the
 * default as any later binding does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AppServiceProvider extends ServiceProvider
{
    /**
     * Bind the application's single-use store.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        // @snippet-start single-use-store-binding
        $this->app->scoped(SingleUseStore::class, ApplicationSingleUseStore::class);
        // @snippet-end single-use-store-binding
    }
}
