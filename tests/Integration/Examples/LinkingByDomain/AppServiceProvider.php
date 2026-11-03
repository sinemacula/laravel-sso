<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\LinkingByDomain;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Links\LinkStore;

/**
 * The example application's service provider (SSO-8.8): it binds the package's
 * link store as the linker, the application's own three linking contracts, each
 * in place of a default that refuses, and its session revocation, in place of
 * the default that revokes nothing. It registers after the package's provider,
 * as an application's providers do, so its bindings replace the defaults as any
 * later binding does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AppServiceProvider extends ServiceProvider
{
    /**
     * Bind the linker and the application's linking contracts.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        // @snippet-start linking-by-domain-bindings
        $this->app->scoped(Linker::class, LinkStore::class);
        $this->app->scoped(LinkEmailMatcher::class, UserEmailMatcher::class);
        $this->app->scoped(PrincipalScope::class, UserPrincipalScope::class);
        $this->app->scoped(TenantMembership::class, UserTenantMembership::class);
        // @snippet-end linking-by-domain-bindings
        $this->app->scoped(SessionRevocation::class, RevokeLinkSessions::class);
    }
}
