<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authentication\Context\ContextContributors;

/**
 * The adapter's service provider, which registers the `sso` contributor.
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
