<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authentication\Context\ContextContributors;

/**
 * The adapter's service provider of
 * `docs/guides/integrating-with-laravel-iam.md` (SSO-9.10, SSO-12.5): in
 * `boot()`, never in configuration, it registers the `sso` contributor with
 * authentication's registry, the examples' stand-in for
 * `laravel-authentication`'s (`IntegratingWithLaravelIam/Authentication`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AdapterServiceProvider extends ServiceProvider
{
    /**
     * Register the adapter's contributor.
     *
     * @return void
     */
    public function boot(): void
    {
        // @snippet-start iam-contributors
        $this->app->make(ContextContributors::class)->register('sso', SsoContextContributor::class);
        // @snippet-end iam-contributors
    }
}
