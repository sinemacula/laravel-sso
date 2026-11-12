<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Links;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Links\LinkStore;

/**
 * The example application's service provider: binds the link store and its own
 * link contracts over the package's defaults.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AppServiceProvider extends ServiceProvider
{
    /**
     * Bind the link store and the application's link contracts.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        // @snippet-start links-linker-binding
        $this->app->scoped(Linker::class, LinkStore::class);
        // @snippet-end links-linker-binding
        // @snippet-start links-limit-binding
        $this->app->singleton(LinkLimit::class, TwoLinksPerConnection::class);
        // @snippet-end links-limit-binding
        // @snippet-start links-confirmation-binding
        $this->app->scoped(LinkConfirmation::class, PasswordSessionsConfirm::class);
        // @snippet-end links-confirmation-binding
        // @snippet-start links-eligibility-binding
        $this->app->singleton(LinkEligibility::class, MembersMayLink::class);
        // @snippet-end links-eligibility-binding
    }
}
