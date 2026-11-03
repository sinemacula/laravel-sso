<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Administration;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Events\AfterCommitDispatcher;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\EventContexts;
use SineMacula\Laravel\Sso\Events\MetadataRefreshed;
use SineMacula\Laravel\Sso\Events\MetadataRefreshFailed;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Reports a refresh of a connection's metadata (SSO-2.8, SSO-10.3): each method
 * builds the event's context through the one projection
 * (`Events\EventContexts`), from the connection's id, tenant and protocol and
 * the acting identity of the administrator who asked for the refresh, `null`
 * for a scheduled one (SSO-10.4), and hands the event to
 * `Events\AfterCommitDispatcher`, so it reaches listeners once the refresh's
 * transaction commits and never when it rolls back (SSO-10.5).
 *
 * The refresh calls it inside the transaction that wrote the refresh or its
 * failure, after the write. No event it builds holds a certificate, a URL or
 * any other value of the metadata: a refresh names the settings it changed,
 * never their values.
 *
 * It holds the projection and the dispatcher, both of which read the clock, the
 * request and the transaction from the container on each call, so nothing of
 * one refresh is kept for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MetadataEvents
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

        /** The dispatcher that waits for the refresh to commit. */
        private AfterCommitDispatcher $dispatcher,
    ) {}

    /**
     * Report the connection's metadata refreshed: the names of the settings it
     * changed, its metadata version after, and whether its trust changed.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  list<string>  $changedSettings
     * @param  int  $metadataVersion
     * @param  bool  $trustChanged
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function refreshed(Connection $connection, array $changedSettings, int $metadataVersion, bool $trustChanged, ?ActingIdentity $actor): void
    {
        $names = array_values(array_unique($changedSettings));

        $this->dispatcher->dispatch(new MetadataRefreshed($this->context($connection, $actor), $names, $metadataVersion, $trustChanged));
    }

    /**
     * Report a refresh of the connection's metadata failed: why, how many have
     * failed in a row, and when the next is due.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  int  $failures
     * @param  ?\Carbon\CarbonImmutable  $nextAttemptAt
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function refreshFailed(Connection $connection, FailureReason $reason, int $failures, ?CarbonImmutable $nextAttemptAt, ?ActingIdentity $actor): void
    {
        $this->dispatcher->dispatch(new MetadataRefreshFailed($this->context($connection, $actor), $reason, $failures, $nextAttemptAt?->utc()));
    }

    /**
     * The context of a refresh of the connection, asked for by the acting
     * identity or by none.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    private function context(Connection $connection, ?ActingIdentity $actor): EventContext
    {
        return $this->contexts->make(
            connectionId: $connection->id,
            connectionTenantId: $connection->tenant_id,
            protocol: $connection->protocol,
            actingIdentityMorphClass: $actor?->type,
            actingIdentityId: $actor?->id,
        );
    }
}
