<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints;

/**
 * Endpoint resolver contract (SSO-5.5): the URLs the package publishes and
 * checks for a connection, its SAML assertion consumer service, its OIDC
 * callback, its service provider entity id and its metadata URL.
 *
 * They are built from configuration and the connection alone, never from the
 * request's host or headers, so a forged `Host` or `X-Forwarded-*` header can
 * neither move an endpoint nor make a response addressed elsewhere pass. A
 * completion is accepted only at the endpoint resolved for the connection its
 * authorisation request names; SAML `Destination` and `Recipient` are compared
 * with the assertion consumer service exactly, and the OIDC callback is sent as
 * `redirect_uri` exactly.
 *
 * The default, `Endpoints\ConfiguredEndpointResolver`, builds each from
 * `sso.endpoints.base_url`, the endpoint's path pattern and the connection's
 * id, with the metadata URL as the entity id; an application with another
 * layout binds its own. `Endpoints\ConnectionEndpoints` refuses any URL that is
 * not an absolute `https` URL (or `http` on a loopback address) with no user
 * information, fragment or wildcard. An implementation keeps nothing of one
 * call for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EndpointResolver
{
    /**
     * The connection's endpoints.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints
     *
     * @throws \InvalidArgumentException
     */
    public function endpoints(SsoConnection $connection): ConnectionEndpoints;
}
