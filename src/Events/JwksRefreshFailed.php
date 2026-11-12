<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * A refetch of an OIDC connection's JWKS on an unknown `kid` failed; the
 * connection keeps the keys it held.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class JwksRefreshFailed implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?\Carbon\CarbonImmutable  $nextRefetchAt
     */
    public function __construct(

        /** Which connection's keys the refetch was for. */
        public EventContext $context,

        /** Why the refetch failed. */
        public FailureReason $reason,

        /** When the next refetch may start, in UTC, once the cooldown ends. */
        public ?CarbonImmutable $nextRefetchAt,
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
