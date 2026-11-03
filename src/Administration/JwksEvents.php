<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Administration;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Events\AfterCommitDispatcher;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\EventContexts;
use SineMacula\Laravel\Sso\Events\JwksRefreshed;
use SineMacula\Laravel\Sso\Events\JwksRefreshFailed;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Reports a refetch of an OIDC connection's JWKS on an unknown `kid` (SSO-7.3,
 * SSO-10.3): each method builds the event's context through the one projection
 * (`Events\EventContexts`), from the connection's id, tenant and protocol, and
 * hands the event to `Events\AfterCommitDispatcher`, so it reaches listeners
 * once the refetch's transaction commits and never when it rolls back
 * (SSO-10.5). A refetch is the completion's, never an administrator's, so no
 * acting identity is named.
 *
 * The refetch calls it inside the transaction that wrote the keys or the
 * failure, after the write. No event it builds holds a key, a URL or any value
 * of the JWKS.
 *
 * It holds the projection and the dispatcher, both of which read the clock, the
 * request and the transaction from the container on each call, so nothing of
 * one refetch is kept for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class JwksEvents
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContexts  $contexts
     * @param  \SineMacula\Laravel\Sso\Events\AfterCommitDispatcher  $dispatcher
     */
    public function __construct(

        /** The projection every event's context is built through. */
        private EventContexts $contexts,

        /** The dispatcher that waits for the refetch to commit. */
        private AfterCommitDispatcher $dispatcher,
    ) {}

    /**
     * Report the connection's JWKS refetched: its version after, the keys added
     * and removed, and whether its trust changed.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  int  $keysAdded
     * @param  int  $keysRemoved
     * @param  bool  $trustChanged
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function refreshed(Connection $connection, int $keysAdded, int $keysRemoved, bool $trustChanged): void
    {
        $this->dispatcher->dispatch(new JwksRefreshed($this->context($connection), $connection->jwks_version, $keysAdded, $keysRemoved, $trustChanged));
    }

    /**
     * Report a refetch of the connection's JWKS failed: why, and when the next
     * may start.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?\Carbon\CarbonImmutable  $nextRefetchAt
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function refreshFailed(Connection $connection, FailureReason $reason, ?CarbonImmutable $nextRefetchAt): void
    {
        $this->dispatcher->dispatch(new JwksRefreshFailed($this->context($connection), $reason, $nextRefetchAt?->utc()));
    }

    /**
     * The context of a refetch of the connection's keys.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    private function context(Connection $connection): EventContext
    {
        return $this->contexts->make(connectionId: $connection->id, connectionTenantId: $connection->tenant_id, protocol: $connection->protocol);
    }
}
