<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * A connection was deleted (SSO-2.1, SSO-10.3), with its domains, links, keys,
 * authorisation requests and handoff codes.
 *
 * Dispatched after the transaction that made the change commits, and never when
 * it rolls back (SSO-10.5). Its context names the connection, its tenant and
 * protocol, and the acting identity as the application passed it (SSO-10.4). It
 * reports only, and holds no secret, private key or setting value; it crosses a
 * queue as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConnectionDeleted implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     */
    public function __construct(

        /** Who made the change, and to which connection. */
        public EventContext $context,
    ) {}

    /**
     * Return who and what the change concerned.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
