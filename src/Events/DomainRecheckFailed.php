<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure;

/**
 * A scheduled check did not confirm a verified domain.
 *
 * A record failure suspends linking and starts the grace period; a failed
 * lookup changes nothing.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DomainRecheckFailed implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  string  $domainId
     * @param  string  $domain
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure  $failure
     * @param  ?\Carbon\CarbonImmutable  $lapsesAt
     */
    public function __construct(

        /** Who acted, if anyone, and the connection that claimed the domain. */
        public EventContext $context,

        /** The claim's id. */
        public string $domainId,

        /** The domain, normalised: lower-case ASCII, no trailing dot. */
        public string $domain,

        /** Why the check did not confirm the domain. */
        public RecheckFailure $failure,

        /** When the domain lapses, in UTC; `null` with no record failure pending. */
        public ?CarbonImmutable $lapsesAt,
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
