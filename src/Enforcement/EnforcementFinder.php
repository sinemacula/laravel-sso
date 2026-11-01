<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;

/**
 * Finds a tenant's enforcement, and the connections it names, always on the
 * write connection (SSO-4.6, SSO-11.3), so neither the answer of
 * `Contracts\Enforcement` nor a change is ever judged against a lagging replica
 * or a cache.
 *
 * A tenant's row is found by the hash of its id (`TenantHash`), and a row whose
 * recorded tenant id is not byte for byte the one given is treated as absent,
 * so `acme` and `Acme` never share a rule, whatever the column's collation. The
 * connections are read in one statement by their ids, in id order, and only
 * those whose tenant and id are exactly the ones given are kept. Locked, the
 * rows stay locked until the transaction the caller has open on the storage
 * connection ends; under a lock every read that decides a write is itself a
 * locking read, since a plain one answers from the snapshot of a transaction
 * the caller opened (MySQL's `REPEATABLE READ`).
 *
 * The tenant id is the application's, so an empty or overlong one is an
 * `InvalidArgumentException`. A database error propagates (SSO-11.4).
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
     * The tenant's enforcement, locked for update when asked, or `null` when it
     * has none stored.
     *
     * @param  string  $tenantId
     * @param  bool  $lock
     * @return ?\SineMacula\Laravel\Sso\Models\TenantEnforcement
     *
     * @throws \InvalidArgumentException
     */
    public function find(string $tenantId, bool $lock = false): ?TenantEnforcement
    {
        self::assertTenant($tenantId);

        $query = TenantEnforcement::query()->useWritePdo()->where('tenant_hash', TenantHash::of($tenantId));

        $enforcement = ($lock ? $query->lockForUpdate() : $query)->first();

        return $enforcement !== null && $enforcement->tenant_id === $tenantId ? $enforcement : null;
    }

    /**
     * The tenant's connections among the ids given, in id order, locked for
     * update when asked: one statement, none when no id is given.
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
     * Refuse a tenant id the enforcement table cannot hold: the application's
     * mistake.
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
