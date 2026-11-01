<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * A session was established in an enforcing tenant under an exemption
 * (SSO-4.4): the exemption contract exempted the identity from the tenant's
 * enforcement, so it was signed in without a satisfying connection.
 *
 * Dispatched once the transaction on the storage connection that established it
 * commits, at once when there is none, and never when it rolls back (SSO-10.5).
 * Its context names the enforcing tenant (`tenantId`), the tenant the session
 * is active in (`activeTenantId`), the application, the identity and, when the
 * caller passed it, the session (SSO-10.4). It reports only; it crosses a queue
 * as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExemptionUsed implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  ?string  $enforcementVersion
     */
    public function __construct(

        /** Who was exempted, from which tenant's enforcement, and where. */
        public EventContext $context,

        /** The version of the enforcement the identity was exempted from. */
        public ?string $enforcementVersion,
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
