<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;

/**
 * A tenant's enforcement rule and connections, locked until the transaction
 * that locked them ends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LockedEnforcement
{
    /**
     * Constructor.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @param  string  $enforcingTenantId
     * @param  ?\SineMacula\Laravel\Sso\Models\TenantEnforcement  $rule
     * @param  list<\SineMacula\Laravel\Sso\Models\Connection>  $connections
     * @param  \Closure(): string  $enforcingNow
     */
    public function __construct(

        /** The tenant asked about. */
        public string $tenantId,

        /** The application asked about. */
        public string $application,

        /** The tenant whose rule applies, as named when the lock was taken. */
        public string $enforcingTenantId,

        /** The enforcing tenant's rule, `null` when it has none stored. */
        public ?TenantEnforcement $rule,

        /** Every connection locked with the rule, in id order. */
        public array $connections,

        /** Asks the inheritance contract for the enforcing tenant again. */
        private \Closure $enforcingNow,
    ) {}

    /**
     * The policy the locked rule gives, judged against the locked connections.
     *
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
     *
     * @throws \InvalidArgumentException
     */
    public function policy(): EnforcementPolicy
    {
        return EnforcementFinder::policyOf($this->tenantId, $this->enforcingTenantId, $this->rule, $this->connections);
    }

    /**
     * The locked connection with the id and tenant, if any.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     */
    public function connection(string $tenantId, string $connectionId): ?Connection
    {
        foreach ($this->connections as $connection) {

            if ($connection->id === $connectionId && $connection->tenant_id === $tenantId) {
                return $connection;
            }
        }

        return null;
    }

    /**
     * Whether the inheritance contract still names the locked enforcing tenant.
     *
     * @return bool
     */
    public function isCurrent(): bool
    {
        return ($this->enforcingNow)() === $this->enforcingTenantId;
    }
}
