<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Finds a tenant's connections for the management helpers (SSO-1.2, SSO-2.11),
 * always on the write connection (SSO-11.3), so a change is never judged
 * against a lagging replica.
 *
 * Every lookup is scoped to a tenant: a connection of another tenant is not
 * found, exactly as an unknown one is not, so a helper never acts on, or
 * reveals, another tenant's connection. The tenant is matched exactly, whatever
 * the column's collation: the statement narrows by `tenant_id`, and a row whose
 * recorded tenant id is not byte for byte the one given is treated as absent,
 * since a collation such as MySQL's default `_ci` counts `acme`, `Acme` and
 * `acme ` as equal. An id that cannot be a connection's (empty, or longer than
 * a ULID) finds nothing without a query. The tenant id is the application's, so
 * an empty or overlong one is an `InvalidArgumentException`. A database error
 * propagates (SSO-11.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ConnectionFinder
{
    /** @var int The longest tenant id the connections table holds, in bytes. */
    public const int MAX_TENANT_ID_LENGTH = 255;

    /** @var int The length of a connection's id, a ULID. */
    private const int ID_LENGTH = 26;

    /**
     * The tenant's connection with the id, or `null` when it has none.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \InvalidArgumentException
     */
    public function find(string $tenantId, string $connectionId): ?Connection
    {
        return $this->lookup($tenantId, $connectionId, false);
    }

    /**
     * The tenant's connection with the id, locked for update until the
     * transaction the caller has open on the storage connection ends, or `null`
     * when it has none.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \InvalidArgumentException
     */
    public function findForUpdate(string $tenantId, string $connectionId): ?Connection
    {
        return $this->lookup($tenantId, $connectionId, true);
    }

    /**
     * Every connection of the tenant, oldest first.
     *
     * @param  string  $tenantId
     * @return list<\SineMacula\Laravel\Sso\Models\Connection>
     *
     * @throws \InvalidArgumentException
     */
    public function forTenant(string $tenantId): array
    {
        self::assertTenant($tenantId);

        $connections = Connection::query()->useWritePdo()->where('tenant_id', $tenantId)->orderBy('created_at')->orderBy('id')->get()->all();

        return array_values(array_filter($connections, static fn (Connection $connection): bool => self::isOf($connection, $tenantId)));
    }

    /**
     * The tenant's connection with the id, locked or not. A row of a tenant the
     * collation merely counts as equal is not found; when locked, it stays
     * locked until the caller's transaction ends, which changes nothing.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  bool  $lock
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \InvalidArgumentException
     */
    private function lookup(string $tenantId, string $connectionId, bool $lock): ?Connection
    {
        self::assertTenant($tenantId);

        if ($connectionId === '' || strlen($connectionId) > self::ID_LENGTH) {
            return null;
        }

        $query = Connection::query()->useWritePdo()->whereKey($connectionId)->where('tenant_id', $tenantId);

        $connection = ($lock ? $query->lockForUpdate() : $query)->first();

        return $connection !== null && self::isOf($connection, $tenantId) ? $connection : null;
    }

    /**
     * Whether the connection records exactly the tenant id. The statement that
     * found it compares under the column's collation, which may count distinct
     * ids, such as `acme` and `Acme`, as equal.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $tenantId
     * @return bool
     */
    private static function isOf(Connection $connection, string $tenantId): bool
    {
        return $connection->tenant_id === $tenantId;
    }

    /**
     * Refuse a tenant id the connections table cannot hold.
     *
     * @param  string  $tenantId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertTenant(string $tenantId): void
    {
        if ($tenantId === '' || strlen($tenantId) > self::MAX_TENANT_ID_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A tenant id is 1 to %d bytes.', self::MAX_TENANT_ID_LENGTH));
        }
    }
}
