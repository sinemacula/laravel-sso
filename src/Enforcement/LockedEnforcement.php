<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;

/**
 * A tenant's enforcement as `DatabaseEnforcement::lock()` locked it (SSO-4.6),
 * for an admission judged under the lock: the tenant asked about and the
 * application, the enforcing tenant the inheritance contract named, the
 * enforcing tenant's rule (`null` while it has none stored: no row, or only the
 * unconfigured guard row), and every connection row locked with it, in id
 * order: the connections the admission goes through and those the rule names.
 *
 * The rows stay locked until the transaction they were locked in ends, so
 * `policy()` answers the rule as it is now and as it stays until then: a change
 * to the rule, or to a satisfying connection, waits for that transaction.
 * `isCurrent()` asks the inheritance contract again, to confirm the lock taken
 * is still the enforcing tenant's; an admission refuses when it is not, rather
 * than take another tenant's lock out of order.
 *
 * It lives only for the transaction its rows were locked in, and holds models
 * and a closure, never a secret.
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

        /** The enforcing tenant's rule, locked, or `null` when it has none stored. */
        public ?TenantEnforcement $rule,

        /** Every connection locked with the rule, in id order. */
        public array $connections,

        /** Names the enforcing tenant again, as the inheritance contract now does. */
        private \Closure $enforcingNow,
    ) {}

    /**
     * The policy the locked rule gives sessions active in the tenant, judged
     * against the locked connections.
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
     * The locked connection with the id, of exactly the tenant, or `null` when
     * none was locked: it is gone, or of another tenant.
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
     * Whether the inheritance contract still names the enforcing tenant whose
     * rule is locked.
     *
     * @return bool
     */
    public function isCurrent(): bool
    {
        return ($this->enforcingNow)() === $this->enforcingTenantId;
    }
}
