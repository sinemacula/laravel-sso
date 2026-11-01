<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;

/**
 * The default enforcement contract (SSO-4.1, SSO-4.2, SSO-4.6): it answers from
 * the package's enforcement table, on the write connection, for the tenant
 * `Contracts\EnforcementInheritance` names, every time it is asked.
 *
 * While the `enforcement` feature is off nothing is required, and nothing is
 * read or asked; a malformed switch fails closed with an
 * `InvalidArgumentException`. Otherwise the inheritance contract, resolved from
 * the container on each call, names the enforcing tenant, and that tenant's row
 * is read: none, or one that is off, requires nothing; one that is on requires
 * one of its stored connections that still exists, belongs to the enforcing
 * tenant byte for byte and is enabled, read in one statement. A rule whose
 * every connection has since gone is still required, and satisfied by none. The
 * policy carries the row's version, so an adapter can recheck a session checked
 * against an older one.
 *
 * Nothing is cached: a change is answered on the next call. A database error
 * propagates (SSO-11.4); it never answers that nothing is required when it
 * cannot tell. An empty or overlong tenant id and an empty application are the
 * application's mistake (`InvalidArgumentException`); an inheritance contract
 * that names no tenant is a `LogicException`.
 *
 * It holds the container and the finder, neither of which keeps anything of one
 * call for the next (SSO-11.2), and is bound scoped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DatabaseEnforcement implements Enforcement
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementFinder  $finder
     */
    public function __construct(

        /** Resolves the inheritance contract on each call. */
        private Container $container,

        /** Reads the rule and its connections, on the write connection. */
        private EnforcementFinder $finder,
    ) {}

    /**
     * The enforcement that applies to sessions active in the tenant, on the
     * application.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function policy(string $tenantId, string $application): EnforcementPolicy
    {
        EnforcementFinder::assertTenant($tenantId);
        self::assertApplication($application);

        if (!Features::enabled(Feature::ENFORCEMENT)) {
            return EnforcementPolicy::notRequired($tenantId, $tenantId, null);
        }

        return $this->stored($tenantId, $this->enforcingTenant($tenantId, $application));
    }

    /**
     * The policy the enforcing tenant's stored rule gives sessions active in
     * the tenant.
     *
     * @param  string  $tenantId
     * @param  string  $enforcingTenantId
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
     *
     * @throws \InvalidArgumentException
     */
    private function stored(string $tenantId, string $enforcingTenantId): EnforcementPolicy
    {
        $enforcement = $this->finder->find($enforcingTenantId);

        if ($enforcement === null || !$enforcement->enabled) {
            return EnforcementPolicy::notRequired($tenantId, $enforcingTenantId, $enforcement?->version);
        }

        $connections = $this->finder->connections($enforcingTenantId, EnforcementSummary::sorted($enforcement->connection_ids));

        return EnforcementPolicy::required($tenantId, $enforcingTenantId, EnforcementFinder::enabledIds($connections), $enforcement->version);
    }

    /**
     * The tenant whose rule applies, as the inheritance contract bound now
     * names it.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @return string
     *
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function enforcingTenant(string $tenantId, string $application): string
    {
        $enforcing = $this->container->make(EnforcementInheritance::class)->enforcingTenant($tenantId, $application);

        self::assertEnforcing($enforcing);

        return $enforcing;
    }

    /**
     * Assert the application a policy is asked for is named.
     *
     * @param  string  $application
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertApplication(string $application): void
    {
        if ($application === '') {
            throw new \InvalidArgumentException('An enforcement policy is asked for an application.');
        }
    }

    /**
     * Assert the inheritance contract named a tenant of 1 to 255 bytes.
     *
     * @param  string  $enforcing
     * @return void
     *
     * @throws \LogicException
     */
    private static function assertEnforcing(string $enforcing): void
    {
        if ($enforcing === '' || strlen($enforcing) > EnforcementFinder::MAX_TENANT_ID_LENGTH) {
            throw new \LogicException(sprintf('The enforcement inheritance contract names a tenant of 1 to %d bytes.', EnforcementFinder::MAX_TENANT_ID_LENGTH));
        }
    }
}
