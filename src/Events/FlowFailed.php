<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;

/**
 * One refused flow, with the first reason that refused it.
 *
 * Its context holds only what the flow established before it was refused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FlowFailed implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     */
    public function __construct(

        /** Who and what the refusal concerned, as far as the flow got. */
        public EventContext $context,

        /** The operation that was refused. */
        public Flow $flow,

        /** Machine-readable reason it was refused. */
        public FailureReason $reason,
    ) {}

    /**
     * Return who and what the refusal concerned.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
