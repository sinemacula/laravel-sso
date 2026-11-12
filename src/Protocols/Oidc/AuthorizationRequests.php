<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Navigation;
use SineMacula\Laravel\Sso\Protocols\Start;
use SineMacula\Laravel\Sso\Protocols\StartRequest;

/**
 * Starts an OpenID Connect authorisation code flow: the redirect to the
 * authorisation endpoint, the expected issuer and whether it returns `iss`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthorizationRequests
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\EndpointResolver  $endpoints
     */
    public function __construct(

        /** The connection's callback, sent as `redirect_uri`. */
        private EndpointResolver $endpoints,
    ) {}

    /**
     * Start the flow, refusing an endpoint whose query already names a
     * parameter the request sets.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Start
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function start(SsoConnection $connection, OidcOptions $options, StartRequest $request): Start
    {
        $callback = $this->endpoints->endpoints($connection)->callback;
        $url      = AuthorizationUrl::build($options->authorizationEndpoint(), $options, $request, $callback);

        if ($url === null) {
            return Start::refused(FailureReason::CONNECTION_UNAVAILABLE);
        }

        return Start::navigate(Navigation::redirect($url), null, $options->issuer(), $options->returnsIss());
    }
}
