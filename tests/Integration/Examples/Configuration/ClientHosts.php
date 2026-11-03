<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Configuration;

/**
 * The example application's own record of the host each client signs in on
 * (SSO-5.5), by the client's tenant, from its own `clients.hosts`
 * configuration: the application's data, never the package's, and never
 * anything from the request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ClientHosts
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The host the client of the tenant signs in on.
     *
     * @param  string  $tenantId
     * @return string
     *
     * @throws \OutOfBoundsException
     */
    public static function for(string $tenantId): string
    {
        $hosts = config('clients.hosts');
        $host  = is_array($hosts) ? ($hosts[$tenantId] ?? null) : null;

        return is_string($host) ? $host : throw new \OutOfBoundsException(sprintf('The client of tenant [%s] has no host.', $tenantId));
    }
}
