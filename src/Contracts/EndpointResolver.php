<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints;

/**
 * Resolves the URLs the package publishes and checks for a connection, which
 * the application serves.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EndpointResolver
{
    /**
     * Build from configuration and the connection only, never from the
     * request's host or forwarded headers.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints
     *
     * @throws \InvalidArgumentException
     */
    public function endpoints(SsoConnection $connection): ConnectionEndpoints;
}
