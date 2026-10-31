<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso;

use Illuminate\Support\ServiceProvider;

/**
 * Package service provider: registers the package's configuration and its
 * publishing tag.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SsoServiceProvider extends ServiceProvider
{
    /**
     * Merge the package's configuration under the `sso` key.
     *
     * Values the application sets in its own `config/sso.php` take precedence
     * over the package's defaults.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/sso.php', 'sso');
    }

    /**
     * Bootstrap the package.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->registerPublishing();
    }

    /**
     * Register the package's config publishing tag.
     *
     * @return void
     */
    private function registerPublishing(): void
    {
        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__ . '/../config/sso.php' => config_path('sso.php'),
        ], 'sso-config');
    }
}
