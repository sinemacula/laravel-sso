<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;

/**
 * A link was created (SSO-8.4, SSO-10.3): a connection's issuer and subject are
 * now associated with an identity, by a redeemed `link` flow, by provisioning,
 * or by a verified domain at redemption.
 *
 * Dispatched after the transaction that created it commits, and never when it
 * rolls back (SSO-10.5). Its context names the connection, its tenant and
 * protocol, the identity the link associates and, for a link made by a flow,
 * the application, the purpose and the request's public reference, and the
 * acting identity where the application passed one (SSO-10.4). It carries how
 * the link was made, never the subject, and crosses a queue as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkCreated implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     */
    public function __construct(

        /** Who and what the link concerns. */
        public EventContext $context,

        /** How the link was made. */
        public LinkOrigin $origin,
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
