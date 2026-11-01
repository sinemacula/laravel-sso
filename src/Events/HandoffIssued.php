<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * A handoff code was issued for a completed flow (SSO-9.2, SSO-10.1).
 *
 * Dispatched after the completion's transaction commits, and never when it
 * rolls back (SSO-10.5). Its context names the connection, its tenant and
 * protocol, the application, the purpose, the request's public reference and
 * the identity the code is bound to, when it is bound to one (SSO-10.4). It
 * never holds the code, and crosses a queue as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class HandoffIssued implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     */
    public function __construct(

        /** Who and what the code concerns. */
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
