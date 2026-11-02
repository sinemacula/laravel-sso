<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * A refetch of an OIDC connection's JWKS on an unknown `kid` failed (SSO-7.3,
 * SSO-10.3): the fetch was refused or failed, the JWKS was refused whole
 * (`jwks_invalid`), what it validated passed its stale limit before the commit
 * (`metadata_expired`), or the refetch lost to a change of the connection made
 * while it fetched (`metadata_conflict`). The connection keeps the keys it
 * held, and no refetch starts again before the cooldown it claimed ends.
 *
 * It carries the reason and when the next refetch may start. Dispatched after
 * the transaction that recorded the failure commits, and never when it rolls
 * back (SSO-10.5). Its context names the connection, its tenant and protocol
 * (SSO-10.4). It never holds the JWKS, a URL or the fetcher's diagnostics,
 * which are logged only through the sanitiser; it crosses a queue as it is.
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
