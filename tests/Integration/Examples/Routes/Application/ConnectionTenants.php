<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes\Application;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Events\ConnectionCreated;
use SineMacula\Laravel\Sso\Events\ConnectionDeleted;

/**
 * The application's own record of each connection's tenant, kept from events.
 * The metadata route needs it: an identity provider names no tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConnectionTenants
{
    /** @var string The application's table. */
    public const string TABLE = 'tenant_sso_connections';

    /**
     * Record the tenant of a connection just created.
     *
     * @param  \SineMacula\Laravel\Sso\Events\ConnectionCreated  $event
     * @return void
     */
    public function remember(ConnectionCreated $event): void
    {
        DB::table(self::TABLE)->insert([
            'connection_id' => (string) $event->context->connectionId,
            'tenant_id'     => (string) $event->context->connectionTenantId,
        ]);
    }

    /**
     * Forget a connection just deleted.
     *
     * @param  \SineMacula\Laravel\Sso\Events\ConnectionDeleted  $event
     * @return void
     */
    public function forget(ConnectionDeleted $event): void
    {
        DB::table(self::TABLE)->where('connection_id', (string) $event->context->connectionId)->delete();
    }

    /**
     * The tenant of the connection, or `null` when it is unknown.
     *
     * @param  string  $connectionId
     * @return ?string
     */
    public function of(string $connectionId): ?string
    {
        $tenantId = DB::table(self::TABLE)->where('connection_id', $connectionId)->value('tenant_id');

        return is_string($tenantId) ? $tenantId : null;
    }
}
