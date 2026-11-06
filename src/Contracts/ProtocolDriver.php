<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Protocols\Start;
use SineMacula\Laravel\Sso\Protocols\StartRequest;

/**
 * Protocol driver contract (SSO-2.2): one protocol behind one contract, which
 * reads a connection's settings, says whether they are complete, starts an
 * authorisation request, reads which request a response answers, validates the
 * response against that request, and describes the service provider side an
 * administrator registers at the identity provider.
 *
 * Drivers are registered on the `Protocols\ProtocolManager` under the name a
 * connection's protocol holds. The package ships `saml2` and `oidc`; an
 * application registers its own with `extend()`. The manager keeps one instance
 * per name for one request or job, building it again by its creator for the
 * next, so a driver must hold no connection, tenant, flow or result state
 * between calls (SSO-11.2), and it never writes a session, issues a token or
 * consumes an authorisation request itself: the package's completion pipeline
 * does that, around the driver.
 *
 * A completion runs in a fixed order (SSO-5.6): `correlate()` reads the
 * request's state from the response without validating anything; the pipeline
 * looks the request up on the write connection and consumes it through the
 * single-use store, so it is consumed once whether the response then passes or
 * fails; `complete()` validates the response against the consumed request.
 * Neither touches the package's storage.
 *
 * Expected refusals are values: `start()` and `complete()` answer a refused
 * outcome with a `FailureReason`, `correlate()` an uncorrelated one, and
 * `describe()` an unavailable one. A database error, a misconfiguration or a
 * library failure propagates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ProtocolDriver
{
    /**
     * The connection settings the values give, typed for this protocol.
     *
     * @param  array<array-key, mixed>  $values
     * @return \SineMacula\Laravel\Sso\Contracts\ProtocolSettings
     */
    public function settings(array $values): ProtocolSettings;

    /**
     * Whether the connection has everything a flow through it needs: its
     * settings, its secrets and its keys or certificates. Only a complete,
     * enabled connection is used (SSO-2.1).
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return bool
     */
    public function isComplete(SsoConnection $connection): bool;

    /**
     * Start an authorisation request at the identity provider: the navigation
     * that sends the browser there, and what the request must keep to complete
     * it, or why it cannot start.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Start
     */
    public function start(SsoConnection $connection, StartRequest $request): Start;

    /**
     * Read which authorisation request the response at the connection's
     * endpoint answers (the OIDC `state`; the SAML `RelayState` and
     * `InResponseTo`), or that it is unsolicited or uncorrelated, without
     * validating anything else in it.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Correlation
     */
    public function correlate(SsoConnection $connection, CompletionRequest $request): Correlation;

    /**
     * Validate the identity provider's response against the authorisation
     * request the pipeline consumed for it, and everything SSO-6 or SSO-7
     * requires, or say why it is refused. The client is the one the response
     * arrived from, which any event the validation records carries (an OIDC
     * driver's JWKS refetch, say); a driver never reads the request itself.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    public function complete(SsoConnection $connection, CompletionRequest $request, ConsumedRequest $consumed, ClientContext $client): Completion;

    /**
     * What an administrator registers at the identity provider (SSO-5.9): the
     * service provider metadata for SAML, the callback URL and public JWKS for
     * OIDC. It never holds a secret.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     */
    public function describe(SsoConnection $connection): ServiceProviderDescription;
}
