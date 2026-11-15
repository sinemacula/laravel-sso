<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Exceptions\EnforcementPathChanged;

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
    /** @var int The most tenants an inheritance path may name. */
    public const int MAX_PATH_LENGTH = 64;

    /** @var string The refusal of a path that is not one, given its limits. */
    private const string MALFORMED_PATH = 'The enforcement inheritance contract names a path of 1 to %d distinct tenants of 1 to %d bytes, from the tenant asked about.';

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

        /** Locks the rows of the inheritance path. */
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

        $path = $this->path($tenantId, $application, $this->isStored(...));

        return $this->stored($tenantId, $path[array_key_last($path)]);
    }

    /**
     * Lock every row of the inheritance path, then the given and named
     * connections in id order; `null`, locking nothing, while the feature is
     * off.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @param  list<string>  $connectionIds
     * @return ?\SineMacula\Laravel\Sso\Enforcement\LockedEnforcement
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\Sso\Exceptions\EnforcementPathChanged
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function lock(string $tenantId, string $application, array $connectionIds): ?LockedEnforcement
    {
        EnforcementFinder::assertTenant($tenantId);
        self::assertApplication($application);

        if (!Features::enabled(Feature::ENFORCEMENT)) {
            return null;
        }

        $path = $this->path($tenantId, $application, $this->isStored(...));
        $rows = $this->lock->acquireEach($path);

        // Asked again of the locked rows alone, so a change committed before
        // the locks is seen; a tenant outside them means the path moved
        $isConfigured = static fn (string $id): bool => EnforcementLock::isConfigured($rows[$id] ?? throw EnforcementPathChanged::retryWhole());

        if ($this->path($tenantId, $application, $isConfigured) !== $path) {
            throw EnforcementPathChanged::retryWhole();
        }

        $enforcing = $path[array_key_last($path)];
        $rule      = EnforcementLock::isConfigured($rows[$enforcing]) ? $rows[$enforcing] : null;
        $named     = $rule?->enabled === true ? $rule->connection_ids : [];
        $locked    = $this->finder->lockConnections(EnforcementSummary::sorted([...$connectionIds, ...$named]));

        return new LockedEnforcement($tenantId, $application, $enforcing, $rule, $locked);
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
     * The inheritance path the contract names, held to its shape.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @param  \Closure(string): bool  $isConfigured
     * @return non-empty-list<string>
     *
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function path(string $tenantId, string $application, \Closure $isConfigured): array
    {
        $path = $this->container->make(EnforcementInheritance::class)->enforcementPath($tenantId, $application, $isConfigured);

        if (!self::isPath($path, $tenantId)) {
            throw new \LogicException(sprintf(self::MALFORMED_PATH, self::MAX_PATH_LENGTH, EnforcementFinder::MAX_TENANT_ID_LENGTH));
        }

        return $path;
    }

    /**
     * Whether the tenant has a stored rule, read without a lock.
     *
     * @param  string  $tenantId
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isStored(string $tenantId): bool
    {
        return $this->finder->find($tenantId) !== null;
    }

    /**
     * Whether the value is a path from the tenant.
     *
     * @param  mixed  $path
     * @param  string  $tenantId
     * @return bool
     *
     * @phpstan-assert-if-true non-empty-list<string> $path
     */
    private static function isPath(mixed $path, string $tenantId): bool
    {
        if (!is_array($path) || !array_is_list($path) || ($path[0] ?? null) !== $tenantId) {
            return false;
        }

        $tenants = array_filter($path, static fn (mixed $id): bool => is_string($id) && $id !== '' && strlen($id) <= EnforcementFinder::MAX_TENANT_ID_LENGTH);

        return count($path) <= self::MAX_PATH_LENGTH && count($tenants) === count($path) && count(array_unique($path)) === count($path);
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
}
