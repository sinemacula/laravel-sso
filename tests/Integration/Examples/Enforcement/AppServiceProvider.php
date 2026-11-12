<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Enforcement;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;

/**
 * The example application's service provider: binds its enforcement
 * inheritance, exemption and session revocation over the package's defaults.
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
