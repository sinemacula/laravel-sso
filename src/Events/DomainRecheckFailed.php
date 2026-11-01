<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure;

/**
 * A scheduled check of a verified domain did not confirm it (SSO-3.3,
 * SSO-11.12): its record was absent or no longer carried the token, which
 * suspends linking by the domain at once and starts the grace period after
 * which it lapses (`lapsesAt`); or the lookup failed, which changes nothing and
 * leaves `lapsesAt` as it was, `null` unless an earlier check set it.
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

        /** When the domain lapses unless a check succeeds first, in UTC; `null` when no record failure is pending. */
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
