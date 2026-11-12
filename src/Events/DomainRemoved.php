<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;

/**
 * A connection's claim of a domain was removed, in whatever state it was, and
 * its open link reservations are void.
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
