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
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Dispatches the events for a JWKS refetch on an unknown `kid`.
 *
 * Call inside the refetch's transaction, after the write.
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
     * Report the connection's JWKS refetched.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  int  $keysAdded
     * @param  int  $keysRemoved
     * @param  bool  $trustChanged
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function refreshed(Connection $connection, int $keysAdded, int $keysRemoved, bool $trustChanged, ClientContext $client): void
    {
        $this->dispatcher->dispatch(new JwksRefreshed($this->context($connection, $client), $connection->jwks_version, $keysAdded, $keysRemoved, $trustChanged));
    }

    /**
     * Report a failed JWKS refetch.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?\Carbon\CarbonImmutable  $nextRefetchAt
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function refreshFailed(Connection $connection, FailureReason $reason, ?CarbonImmutable $nextRefetchAt, ClientContext $client): void
    {
        $this->dispatcher->dispatch(new JwksRefreshFailed($this->context($connection, $client), $reason, $nextRefetchAt?->utc()));
    }

    /**
     * The context of a refetch, which never has an acting identity.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    private function context(Connection $connection, ClientContext $client): EventContext
    {
        return $this->contexts->make($client, connectionId: $connection->id, connectionTenantId: $connection->tenant_id, protocol: $connection->protocol);
    }
}
