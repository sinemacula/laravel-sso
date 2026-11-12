<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\SingleUseStore;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;

/**
 * Binds the application's single-use store in place of the package's default.
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
