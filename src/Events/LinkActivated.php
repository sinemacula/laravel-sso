<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * A link reservation was activated by the redemption of its handoff (SSO-8.8):
 * a person's existing identity is now linked by a verified domain, which the
 * application should tell them about on their existing channels.
 *
 * Dispatched after the transaction that activated it commits, right after
 * `LinkCreated`, and never when it rolls back (SSO-10.5). It carries references
 * sufficient to notify the person (the connection, its tenant and protocol, the
 * identity, the application, the request's public reference and the link),
 * never the email the provider supplied, which must never be used as a
 * notification destination, and crosses a queue as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkActivated implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     */
    public function __construct(

        /** The link activated. */
        public string $linkId,

        /** Who and what the activation concerns. */
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
