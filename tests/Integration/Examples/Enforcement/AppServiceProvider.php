<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Enforcement;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;

/**
 * The example application's service provider (SSO-4.2, SSO-4.4, SSO-4.5): it
 * binds the application's tenant tree as the enforcement inheritance, its
 * break-glass administrator as the exemption, and its own session revocation,
 * each in place of the package's default. It registers after the package's
 * provider, as an application's providers do, so its bindings replace the
 * defaults as any later binding does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AppServiceProvider extends ServiceProvider
{
    /**
     * Bind the application's enforcement contracts.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        // @snippet-start enforcement-inheritance-binding
        $this->app->singleton(EnforcementInheritance::class, TenantTreeInheritance::class);
        // @snippet-end enforcement-inheritance-binding
        $this->app->singleton(EnforcementExemption::class, BreakGlassExemption::class);
        $this->app->singleton(SessionRevocation::class, RevokeSessions::class);
    }
}
