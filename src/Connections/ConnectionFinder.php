<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Finds a tenant's connections on the write connection, treating another
 * tenant's connection exactly as an unknown one.
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
     * The tenant's connection with the id, locked for update in the caller's
     * transaction, or `null` when it has none.
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
     * The tenant's connection with the id, locked or not.
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
     * Byte-exact tenant match, since a case-insensitive collation such as
     * MySQL's `_ci` counts `acme` and `Acme` as equal.
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
