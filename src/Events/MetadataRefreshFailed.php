<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * A refresh of a connection's metadata failed; the connection keeps its last
 * good settings until they expire.
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

        /** Who asked for the refresh, if anyone, and for which connection. */
        public EventContext $context,

        /** Why the refresh failed. */
        public FailureReason $reason,

        /** How many refreshes have failed in a row, this one included. */
        public int $failures,

        /** When the next scheduled refresh is due, in UTC; `null` when none is. */
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
