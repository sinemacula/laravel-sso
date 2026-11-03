<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Queue;

use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints;

/**
 * An application's endpoint resolver for one scope, as one that depends on the
 * job or request it was built for would be: every endpoint is under the host
 * given, so an answer shows which scope's instance gave it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ScopedEndpoints implements EndpointResolver
{
    /**
     * Constructor.
     *
     * @param  string  $host
     */
    public function __construct(

        /** The host every endpoint is under. */
        private string $host,
    ) {}

    /**
     * The connection's endpoints, under the host.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints
     */
    #[\Override]
    public function endpoints(SsoConnection $connection): ConnectionEndpoints
    {
        $base = "https://{$this->host}/{$connection->getConnectionId()}";

        return new ConnectionEndpoints("{$base}/acs", "{$base}/callback", "{$base}/metadata", "{$base}/metadata", "{$base}/jwks");
    }
}
