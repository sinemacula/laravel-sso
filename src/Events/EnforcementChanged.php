<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * A tenant's enforcement changed (SSO-4.5, SSO-10.3): turned on or off, or the
 * connections that satisfy it changed, with a new `version`. Any revocation the
 * change needed ran in the same transaction, through the synchronous revocation
 * contract; this event only reports it.
 *
 * Dispatched after the transaction that made the change commits, and never when
 * it rolls back (SSO-10.5). Its context names the tenant and the acting
 * identity as the application passed it (SSO-10.4). It reports only; it crosses
 * a queue as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EnforcementChanged implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  bool  $enabled
     * @param  list<string>  $connectionIds
     * @param  string  $version
     * @param  ?string  $previousVersion
     */
    public function __construct(

        /** Who made the change, and to what. */
        public EventContext $context,

        /** Whether the tenant now requires sign-in through a satisfying connection. */
        public bool $enabled,

        /** The ids of the connections that now satisfy it, in id order. */
        public array $connectionIds,

        /** The version the change gave the tenant's enforcement. */
        public string $version,

        /** The version before the change; `null` when the tenant had none stored. */
        public ?string $previousVersion,
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
