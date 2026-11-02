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
 * Starts an OpenID Connect authorisation code flow (SSO-5.4, SSO-5.10, SSO-2.4,
 * `docs/design/oidc-requests.md`): the redirect to the connection's
 * authorisation endpoint, and the issuer the response must come from and
 * whether it must carry `iss` (SSO-7.1).
 *
 * - The URL is `AuthorizationUrl`'s: `response_type=code`, the client id, the
 *   connection's callback as `redirect_uri`, the scopes, the flow's `state`,
 *   `nonce` and PKCE S256 challenge, `max_age=0` and `prompt=login` for a
 *   `reauthenticate`, then the connection's extra parameters.
 * - The callback is the endpoint resolver's, never the request's (SSO-5.5).
 * - The answer is `Start::navigate()` with a redirect, no SAML request id, the
 *   connection's issuer exactly as configured, and whether the provider returns
 *   the RFC 9207 `iss` (`returns_iss`, which import and refresh set when the
 *   discovery document advertises it). The start pipeline stores them with the
 *   request, beside the digests of the state and the nonce, the PKCE verifier
 *   encrypted and the connection's trust version.
 * - An authorisation endpoint whose own query names a parameter the request
 *   sets is refused with `connection_unavailable`, never overridden.
 *
 * The driver checks the metadata expiry first, and only a complete connection
 * is started. A start makes no network call, and nothing here logs or reports
 * the request or its values. It holds the endpoint resolver alone, which keeps
 * nothing between calls (SSO-11.2).
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
     * Start the flow for the connection, or refuse it.
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
