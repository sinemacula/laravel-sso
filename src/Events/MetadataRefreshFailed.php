<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * A refresh of a connection's metadata failed (SSO-2.8, SSO-10.3): the fetch
 * was refused or failed, the metadata was invalid, unsigned or signed by no
 * anchor, did not hold the pinned entity, or lost to a change of the connection
 * made while it fetched. The connection keeps its last good settings, until
 * they expire (`metadata_expired`).
 *
 * It carries the reason, how many refreshes have failed in a row, and when the
 * next is due after the backoff. Dispatched after the transaction that recorded
 * the failure commits, and never when it rolls back (SSO-10.5). Its context
 * names the connection, its tenant and protocol, and the acting identity when
 * an administrator asked for the refresh (SSO-10.4). It never holds the
 * metadata, a URL or the fetcher's diagnostics, which are logged only through
 * the sanitiser; it crosses a queue as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MetadataRefreshFailed implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  int  $failures
     * @param  ?\Carbon\CarbonImmutable  $nextAttemptAt
     */
    public function __construct(

        /** Who asked for the refresh, if anyone, and which connection it was for. */
        public EventContext $context,

        /** Why the refresh failed. */
        public FailureReason $reason,

        /** How many refreshes of the connection have failed in a row, this one included. */
        public int $failures,

        /** When the next scheduled refresh is due, in UTC, or `null` when none is scheduled. */
        public ?CarbonImmutable $nextAttemptAt,
    ) {}

    /**
     * Return who and what the failure concerned.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
