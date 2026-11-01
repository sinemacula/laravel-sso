<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * A handoff code was redeemed (SSO-9.2, SSO-9.9, SSO-10.1), by the package's
 * own redemption helper.
 *
 * Dispatched after the redemption's transaction commits, and never when it
 * rolls back (SSO-10.5). Its context names the connection, its tenant and
 * protocol, the application, the purpose, the request's public reference and
 * the identity the code resolved to or was bound to (SSO-10.4). It never holds
 * the code or the verifier, and crosses a queue as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class HandoffRedeemed implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     */
    public function __construct(

        /** Who and what the redemption concerns. */
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
