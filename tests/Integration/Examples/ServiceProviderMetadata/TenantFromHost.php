<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\ServiceProviderMetadata;

use Illuminate\Http\Request;

/**
 * The example application's tenancy middleware, resolving the tenant from the
 * request's host.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantFromHost
{
    /** @var array<string, string> The tenant each host the application serves is for. */
    public const array TENANTS = [
        'sp.example.test'    => 'tenant-1',
        'other.example.test' => 'tenant-2',
    ];

    /**
     * Resolve the request's tenant, for the route to read.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): mixed  $next
     * @return mixed
     */
    public function handle(Request $request, \Closure $next): mixed
    {
        $tenantId = self::TENANTS[$request->getHost()] ?? null;

        abort_if($tenantId === null, 404);

        $request->attributes->set('tenant_id', $tenantId);

        return $next($request);
    }
}
