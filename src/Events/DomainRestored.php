<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * A verified domain whose record had gone passed a check again within its grace
 * period (SSO-3.3): linking by it resumes and it no longer lapses. Its
 * verification time is unchanged.
 *
 * Dispatched after the transaction that made the change commits, and never when
 * it rolls back (SSO-10.5). Its context names the connection, its tenant and
 * protocol; a scheduled check has no acting identity (SSO-10.4). It reports
 * only, and never holds the verification token or a record's value; it crosses
 * a queue as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DomainRestored implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  string  $domainId
     * @param  string  $domain
     * @param  \Carbon\CarbonImmutable  $verifiedAt
     * @param  \Carbon\CarbonImmutable  $checkedAt
     */
    public function __construct(

        /** Who acted, if anyone, and the connection that claimed the domain. */
        public EventContext $context,

        /** The claim's id. */
        public string $domainId,

        /** The domain, normalised: lower-case ASCII, no trailing dot. */
        public string $domain,

        /** When the domain became verified, kept across the restoration, in UTC. */
        public CarbonImmutable $verifiedAt,

        /** When the check that confirmed it again ran, its last successful check, in UTC. */
        public CarbonImmutable $checkedAt,
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
