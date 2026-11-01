<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * A link was removed (SSO-8.4, SSO-10.3): the identity's sessions established
 * through the connection were revoked in the same transaction (SSO-4.5).
 *
 * Dispatched after the transaction that removed it commits, and never when it
 * rolls back (SSO-10.5). Its context names the connection, its tenant and
 * protocol, the identity the link associated, and the acting identity as the
 * application passed it (SSO-10.4). It never holds the subject, and crosses a
 * queue as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkRemoved implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     */
    public function __construct(

        /** Who removed the link, and whose it was. */
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
