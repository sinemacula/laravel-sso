<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;

/**
 * Reads a tenant's enforcement and its connections from the write connection,
 * never a lagging replica; tenant and connection ids match byte for byte.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnforcementFinder
{
    /** @var int The longest tenant id the enforcement table holds, in bytes. */
    public const int MAX_TENANT_ID_LENGTH = 255;

    /**
     * The tenant's enforcement, `null` for no row or an unconfigured one.
     *
     * @param  string  $tenantId
     * @param  bool  $lock
     * @return ?\SineMacula\Laravel\Sso\Models\TenantEnforcement
     *
     * @throws \InvalidArgumentException
     */
    public function find(string $tenantId, bool $lock = false): ?TenantEnforcement
    {
        $enforcement = $this->row($tenantId, $lock);

        return $enforcement?->version === null ? null : $enforcement;
    }

    /**
     * The tenant's row, configured or not.
     *
     * @param  string  $tenantId
     * @param  bool  $lock
     * @return ?\SineMacula\Laravel\Sso\Models\TenantEnforcement
     *
     * @throws \InvalidArgumentException
     */
    public function row(string $tenantId, bool $lock = false): ?TenantEnforcement
    {
        self::assertTenant($tenantId);

        $query = TenantEnforcement::query()->useWritePdo()->where('tenant_hash', TenantHash::of($tenantId));

        $enforcement = ($lock ? $query->lockForUpdate() : $query)->first();

        return $enforcement !== null && $enforcement->tenant_id === $tenantId ? $enforcement : null;
    }

    /**
     * Lock the connections with the ids given, of any tenant, in id order.
     *
     * @param  list<string>  $ids
     * @return list<\SineMacula\Laravel\Sso\Models\Connection>
     */
    public function lockConnections(array $ids): array
    {
        if ($ids === []) {
            return [];
        }

        return array_values(Connection::query()->useWritePdo()->whereIn('id', $ids)->orderBy('id')->lockForUpdate()->get()->all());
    }

    /**
     * The policy the rule gives, satisfied by the enforcing tenant's enabled
     * connections among those given that the rule names.
     *
     * @param  string  $tenantId
     * @param  string  $enforcingTenantId
     * @param  ?\SineMacula\Laravel\Sso\Models\TenantEnforcement  $rule
     * @param  list<\SineMacula\Laravel\Sso\Models\Connection>  $connections
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
     *
     * @throws \InvalidArgumentException
     */
    public static function policyOf(string $tenantId, string $enforcingTenantId, ?TenantEnforcement $rule, array $connections): EnforcementPolicy
    {
        if ($rule === null || !$rule->enabled) {
            return EnforcementPolicy::notRequired($tenantId, $enforcingTenantId, $rule?->version);
        }

        $named        = EnforcementSummary::sorted($rule->connection_ids);
        $isSatisfying = static fn (Connection $connection): bool => $connection->tenant_id === $enforcingTenantId && in_array($connection->id, $named, true);
        $satisfying   = array_filter($connections, $isSatisfying);

        return EnforcementPolicy::required($tenantId, $enforcingTenantId, self::enabledIds(array_values($satisfying)), (string) $rule->version);
    }

    /**
     * The tenant's connections among the ids given, in id order.
     *
     * @param  string  $tenantId
     * @param  list<string>  $ids
     * @param  bool  $lock
     * @return list<\SineMacula\Laravel\Sso\Models\Connection>
     *
     * @throws \InvalidArgumentException
     */
    public function connections(string $tenantId, array $ids, bool $lock = false): array
    {
        self::assertTenant($tenantId);

        if ($ids === []) {
            return [];
        }

        $query = Connection::query()->useWritePdo()->whereIn('id', $ids)->orderBy('id');

        $connections = ($lock ? $query->lockForUpdate() : $query)->get()->all();

        $isNamed = static fn (Connection $connection): bool => $connection->tenant_id === $tenantId && in_array($connection->id, $ids, true);

        return array_values(array_filter($connections, $isNamed));
    }

    /**
     * The ids of the connections that are enabled, in the order given.
     *
     * @param  list<\SineMacula\Laravel\Sso\Models\Connection>  $connections
     * @return list<string>
     */
    public static function enabledIds(array $connections): array
    {
        $enabled = array_filter($connections, static fn (Connection $connection): bool => $connection->enabled);

        return array_values(array_map(static fn (Connection $connection): string => $connection->id, $enabled));
    }

    /**
     * Refuse a tenant id the enforcement table cannot hold.
     *
     * @param  string  $tenantId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertTenant(string $tenantId): void
    {
        if ($tenantId === '' || strlen($tenantId) > self::MAX_TENANT_ID_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A tenant id is 1 to %d bytes.', self::MAX_TENANT_ID_LENGTH));
        }
    }
}
