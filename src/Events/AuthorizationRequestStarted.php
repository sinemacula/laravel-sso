<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * An authorisation request was started (SSO-5.1, SSO-10.1): the client was sent
 * on to the identity provider. A discovery miss starts no request and reports
 * `FlowFailed` with `discovery_no_match` instead (SSO-3.5).
 *
 * Dispatched after the transaction that stored the request commits, and never
 * when it rolls back (SSO-10.5). Its context names the connection, its tenant
 * and protocol, the application, the purpose and the request's public
 * reference, the identity of a `link` or `reauthenticate` flow and the session
 * of a `reauthenticate` flow (SSO-10.4). It holds no protocol state, nonce or
 * verifier, and crosses a queue as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuthorizationRequestStarted implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     */
    public function __construct(

        /** Who and what the request concerns. */
        public EventContext $context,
    ) {}

    /**
     * Return who and what the event concerns.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
