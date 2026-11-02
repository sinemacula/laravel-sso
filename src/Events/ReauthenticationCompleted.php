<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * A `reauthenticate` handoff was redeemed and the session's authentication time
 * renewed (SSO-5.10, SSO-9.5).
 *
 * Dispatched only once the transaction that wrote the renewal commits, and
 * never when it rolls back (SSO-10.5). Its context names the connection, its
 * tenant and protocol, the application, the request's public reference, the
 * identity and the session, never a subject or an authentication context, and
 * it crosses a queue as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ReauthenticationCompleted implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     */
    public function __construct(

        /** Who and what the event concerns. */
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
