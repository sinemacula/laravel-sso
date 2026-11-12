<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;

/**
 * Default enforcement contract, read uncached from the enforcement table.
 *
 * `policy()` takes no lock; an admission that must not race a rule change calls
 * `lock()` inside its transaction on the storage connection.
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
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementLock  $lock
     */
    public function __construct(

        /** Resolves the inheritance contract on each call. */
        private Container $container,

        /** Reads the rule and its connections, on the write connection. */
        private EnforcementFinder $finder,

        /** Locks the enforcing tenant's row. */
        private EnforcementLock $lock,
    ) {}

    /**
     * The enforcement for sessions in the tenant on the application.
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
     * Lock the enforcing tenant's row, then the given and named connections in
     * id order; `null`, locking nothing, while the feature is off.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @param  list<string>  $connectionIds
     * @return ?\SineMacula\Laravel\Sso\Enforcement\LockedEnforcement
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function lock(string $tenantId, string $application, array $connectionIds): ?LockedEnforcement
    {
        EnforcementFinder::assertTenant($tenantId);
        self::assertApplication($application);

        if (!Features::enabled(Feature::ENFORCEMENT)) {
            return null;
        }

        $enforcing = $this->enforcingTenant($tenantId, $application);
        $row       = $this->lock->acquire($enforcing);
        $rule      = EnforcementLock::isConfigured($row) ? $row : null;
        $named     = $rule?->enabled === true ? $rule->connection_ids : [];
        $locked    = $this->finder->lockConnections(EnforcementSummary::sorted([...$connectionIds, ...$named]));

        return new LockedEnforcement($tenantId, $application, $enforcing, $rule, $locked, fn (): string => $this->enforcingTenant($tenantId, $application));
    }

    /**
     * The policy the enforcing tenant's stored rule gives.
     *
     * @param  string  $tenantId
     * @param  string  $enforcingTenantId
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
     *
     * @throws \InvalidArgumentException
     */
    private function stored(string $tenantId, string $enforcingTenantId): EnforcementPolicy
    {
        $rule        = $this->finder->find($enforcingTenantId);
        $connections = $rule?->enabled === true ? $this->finder->connections($enforcingTenantId, EnforcementSummary::sorted($rule->connection_ids)) : [];

        return EnforcementFinder::policyOf($tenantId, $enforcingTenantId, $rule, $connections);
    }

    /**
     * The tenant whose rule applies, as the inheritance contract names it.
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
