<?php

declare(strict_types = 1);

namespace Tests;

use Composer\InstalledVersions;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Router;
use SineMacula\Laravel\Sso\Applications\ConfiguredApplicationPolicy;
use SineMacula\Laravel\Sso\Applications\ConfiguredRedirectUriResolver;
use SineMacula\Laravel\Sso\Clock\SystemClock;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\HostResolver;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\ProviderSessionDeadline;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\RedirectUriResolver;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Domains\SystemDnsResolver;
use SineMacula\Laravel\Sso\Endpoints\ConfiguredEndpointResolver;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Enforcement\NoExemptions;
use SineMacula\Laravel\Sso\Enforcement\OwnTenantInheritance;
use SineMacula\Laravel\Sso\Evidence\InsufficientEvidence;
use SineMacula\Laravel\Sso\Fetching\GuzzleFetcher;
use SineMacula\Laravel\Sso\Fetching\SystemHostResolver;
use SineMacula\Laravel\Sso\Flows\NoReauthenticationSessions;
use SineMacula\Laravel\Sso\Freshness\RefusingFreshness;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Linking\NoEmailMatches;
use SineMacula\Laravel\Sso\Linking\NoTenantMembership;
use SineMacula\Laravel\Sso\Linking\RefusingLinkConfirmation;
use SineMacula\Laravel\Sso\Linking\RefusingLinkEligibility;
use SineMacula\Laravel\Sso\Linking\RefusingPrincipalScope;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Links\OneLinkPerConnection;
use SineMacula\Laravel\Sso\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Sso\Results\ProviderDeadlineLimitsSession;
use SineMacula\Laravel\Sso\Revocation\NoSessionRevocation;
use SineMacula\Laravel\Sso\Secrets\LaravelSecretEncrypter;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;

/**
 * Base for acceptance tests of the package alone, with no sibling, package
 * discovery, session middleware or binding beyond the provider's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class StandaloneTestCase extends TestCase
{
    /** @var array<class-string, class-string> Each seam and the default the package binds it to. */
    protected const array DEFAULT_BINDINGS = [
        SingleUseStore::class           => DatabaseSingleUseStore::class,
        Fetcher::class                  => GuzzleFetcher::class,
        AttemptLimiter::class           => DatabaseAttemptLimiter::class,
        Freshness::class                => RefusingFreshness::class,
        Enforcement::class              => DatabaseEnforcement::class,
        EnforcementInheritance::class   => OwnTenantInheritance::class,
        EnforcementExemption::class     => NoExemptions::class,
        SessionRevocation::class        => NoSessionRevocation::class,
        ApplicationPolicy::class        => ConfiguredApplicationPolicy::class,
        RedirectUriResolver::class      => ConfiguredRedirectUriResolver::class,
        EndpointResolver::class         => ConfiguredEndpointResolver::class,
        Linker::class                   => NoLinks::class,
        LinkLimit::class                => OneLinkPerConnection::class,
        ReauthenticationSessions::class => NoReauthenticationSessions::class,
        LinkEligibility::class          => RefusingLinkEligibility::class,
        LinkConfirmation::class         => RefusingLinkConfirmation::class,
        LinkEmailMatcher::class         => NoEmailMatches::class,
        PrincipalScope::class           => RefusingPrincipalScope::class,
        TenantMembership::class         => NoTenantMembership::class,
        EvidencePolicy::class           => InsufficientEvidence::class,
        ProviderSessionDeadline::class  => ProviderDeadlineLimitsSession::class,
        HandoffIssuer::class            => DatabaseHandoffStore::class,
        Clock::class                    => SystemClock::class,
        DnsResolver::class              => SystemDnsResolver::class,
        HostResolver::class             => SystemHostResolver::class,
        SecretEncrypter::class          => LaravelSecretEncrypter::class,
    ];

    /** @var string What every sibling package's Composer name starts with. */
    private const string SIBLING_PREFIX = 'sinemacula/laravel-';

    /** @var string This package's Composer name. */
    private const string THIS_PACKAGE = 'sinemacula/laravel-sso';

    /** @var list<string> What a session or its forgery check in a middleware group would be named by. */
    private const array SESSION_MIDDLEWARE = ['Session', 'VerifyCsrf', 'Forgery', 'ShareErrors'];

    /**
     * Remove the skeleton's middleware groups from the kernel and the router,
     * which keeps its own copy, so nothing a test serves has a session.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Orchestra\Testbench\Http\Kernel $kernel */
        $kernel = $this->app?->make(Kernel::class);

        $kernel->setMiddlewareGroups([]);

        $router = $this->router();

        foreach (array_keys($router->getMiddlewareGroups()) as $group) {
            $router->middlewareGroup((string) $group, []);
        }
    }

    /**
     * Assert no sibling is installed and no session middleware is registered.
     *
     * @return void
     */
    protected function assertStandalone(): void
    {
        static::assertSame([], self::siblingsAmong(InstalledVersions::getInstalledPackages()), 'A sibling package is installed.');

        foreach ($this->sessionMiddleware() as $middleware) {
            static::fail("The application names the session middleware {$middleware}.");
        }
    }

    /**
     * Those of the Composer packages that are siblings of this one.
     *
     * @param  list<string>  $packages
     * @return list<string>
     */
    protected static function siblingsAmong(array $packages): array
    {
        return array_values(array_filter(
            $packages,
            static fn (string $package): bool => str_starts_with($package, self::SIBLING_PREFIX) && $package !== self::THIS_PACKAGE,
        ));
    }

    /**
     * Assert every seam is still bound to the package's default.
     *
     * @return void
     */
    protected function assertDefaultBindings(): void
    {
        foreach (self::DEFAULT_BINDINGS as $seam => $default) {
            static::assertInstanceOf($default, $this->app?->make($seam), "{$seam} is not bound to its default.");
        }
    }

    /**
     * Every session middleware the kernel or the router holds.
     *
     * @return list<string>
     */
    private function sessionMiddleware(): array
    {
        /** @var \Orchestra\Testbench\Http\Kernel $kernel */
        $kernel = $this->app?->make(Kernel::class);

        $named = [
            ...$kernel->getGlobalMiddleware(),
            ...array_merge([], ...array_values($kernel->getMiddlewareGroups())),
            ...array_merge([], ...array_values($this->router()->getMiddlewareGroups())),
        ];

        return array_values(array_filter($named, static function (string $middleware): bool {

            foreach (self::SESSION_MIDDLEWARE as $word) {
                if (str_contains($middleware, $word)) {
                    return true;
                }
            }

            return false;
        }));
    }

    /**
     * The application's router.
     *
     * @return \Illuminate\Routing\Router
     */
    private function router(): Router
    {
        $router = $this->app?->make('router');

        static::assertInstanceOf(Router::class, $router);

        return $router;
    }
}
