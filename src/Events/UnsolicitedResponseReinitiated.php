<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * An unsolicited SAML response passed the unsolicited profile and was answered
 * with re-initiation (SSO-5.8, SSO-10.1): its assertion was recorded against
 * replay and the browser sent to the connection's start URL. Nobody was signed
 * in.
 *
 * Dispatched after the transaction that recorded the assertion commits, and
 * never when it rolls back (SSO-10.5). Its context names the connection, its
 * tenant and protocol and the request context (SSO-10.4); there is no
 * authorisation request, application or identity. It never holds the response,
 * its subject or the identity provider's `RelayState`, and crosses a queue as
 * it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class UnsolicitedResponseReinitiated implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     */
    public function __construct(

        /** Which connection the response arrived for. */
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
