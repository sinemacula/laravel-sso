<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes\Application;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Events\ConnectionCreated;
use SineMacula\Laravel\Sso\Events\ConnectionDeleted;

/**
 * The example application's own record of which tenant each connection belongs
 * to (SSO-12.5), kept from the package's events, for the routes an identity
 * provider calls with a connection id and no tenant: the service provider
 * metadata.
 *
 * It writes the application's own table, never one of the package's.
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
     * The tenant of the connection, or `null` when the application has no
     * record of it.
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
