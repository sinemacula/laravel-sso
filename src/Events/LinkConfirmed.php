<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * A person confirmed a link through the `link` purpose (SSO-8.8, SSO-5.11): the
 * link's verified domain provenance, and any suspension it held, are cleared
 * for good.
 *
 * Dispatched after the transaction that confirmed it commits, and never when it
 * rolls back (SSO-10.5). Its context names the connection, its tenant and
 * protocol, the identity, the application and the request's public reference,
 * never the subject, and it crosses a queue as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkConfirmed implements SsoEvent
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
