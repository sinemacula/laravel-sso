<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;

/**
 * A connection's claim of a domain was removed (SSO-3, SSO-10.3), in whatever
 * state it was; a verified domain no longer routes discovery or allows linking,
 * and its open link reservations are void.
 *
 * Dispatched after the transaction that made the change commits, and never when
 * it rolls back (SSO-10.5). Its context names the connection, its tenant and
 * protocol, and the acting identity as the application passed it (SSO-10.4). It
 * reports only, and never holds the verification token or a record's value; it
 * crosses a queue as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DomainRemoved implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  string  $domainId
     * @param  string  $domain
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\DomainState  $state
     */
    public function __construct(

        /** Who acted, if anyone, and the connection that claimed the domain. */
        public EventContext $context,

        /** The claim's id. */
        public string $domainId,

        /** The domain, normalised: lower-case ASCII, no trailing dot. */
        public string $domain,

        /** The state the claim was in when it was removed. */
        public DomainState $state,
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
