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
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Dispatches the events for a connection's metadata refresh.
 *
 * Call inside the refresh's transaction, after the write.
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
     * Report the connection's metadata refreshed, naming changed settings only.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  list<string>  $changedSettings
     * @param  int  $metadataVersion
     * @param  bool  $trustChanged
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function refreshed(Connection $connection, array $changedSettings, int $metadataVersion, bool $trustChanged, ?Caller $caller, ClientContext $client): void
    {
        $names = array_values(array_unique($changedSettings));

        $this->dispatcher->dispatch(new MetadataRefreshed($this->context($connection, $caller, $client), $names, $metadataVersion, $trustChanged));
    }

    /**
     * Report a failed metadata refresh.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  int  $failures
     * @param  ?\Carbon\CarbonImmutable  $nextAttemptAt
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function refreshFailed(Connection $connection, FailureReason $reason, int $failures, ?CarbonImmutable $nextAttemptAt, ?Caller $caller, ClientContext $client): void
    {
        $this->dispatcher->dispatch(new MetadataRefreshFailed($this->context($connection, $caller, $client), $reason, $failures, $nextAttemptAt?->utc()));
    }

    /**
     * The context of a refresh; no caller for a scheduled one.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    private function context(Connection $connection, ?Caller $caller, ClientContext $client): EventContext
    {
        return $this->contexts->make(
            $client,
            connectionId: $connection->id,
            connectionTenantId: $connection->tenant_id,
            protocol: $connection->protocol,
            actingIdentityMorphClass: $caller?->identity->type,
            actingIdentityId: $caller?->identity->id,
        );
    }
}
