<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Administration;

use SineMacula\Laravel\Sso\Events\AfterCommitDispatcher;
use SineMacula\Laravel\Sso\Events\ConnectionCreated;
use SineMacula\Laravel\Sso\Events\ConnectionDeleted;
use SineMacula\Laravel\Sso\Events\ConnectionDisabled;
use SineMacula\Laravel\Sso\Events\ConnectionEnabled;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\EventContexts;
use SineMacula\Laravel\Sso\Events\KeyAdded;
use SineMacula\Laravel\Sso\Events\KeyMadeCurrent;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;
use SineMacula\Laravel\Sso\Events\KeyRetired;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;

/**
 * Dispatches the events for management changes to connections and keys.
 *
 * Call inside the change's transaction, after the write, once per real change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AdministrationEvents
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

        /** The dispatcher that waits for the change to commit. */
        private AfterCommitDispatcher $dispatcher,
    ) {}

    /**
     * Report a connection created.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function connectionCreated(Connection $connection, ?Caller $caller, ClientContext $client): void
    {
        $this->dispatcher->dispatch(new ConnectionCreated($this->context($connection, $caller, $client)));
    }

    /**
     * Report a connection's changed setting names; nothing when none changed.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  list<string>  $changedSettings
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function connectionUpdated(Connection $connection, array $changedSettings, ?Caller $caller, ClientContext $client): void
    {
        $names = array_values(array_unique($changedSettings));

        if ($names === []) {
            return;
        }

        $this->dispatcher->dispatch(new ConnectionUpdated($this->context($connection, $caller, $client), $names));
    }

    /**
     * Report a connection enabled.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function connectionEnabled(Connection $connection, ?Caller $caller, ClientContext $client): void
    {
        $this->dispatcher->dispatch(new ConnectionEnabled($this->context($connection, $caller, $client)));
    }

    /**
     * Report a connection disabled.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function connectionDisabled(Connection $connection, ?Caller $caller, ClientContext $client): void
    {
        $this->dispatcher->dispatch(new ConnectionDisabled($this->context($connection, $caller, $client)));
    }

    /**
     * Report a connection deleted, given the row as read before the delete.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function connectionDeleted(Connection $connection, ?Caller $caller, ClientContext $client): void
    {
        $this->dispatcher->dispatch(new ConnectionDeleted($this->context($connection, $caller, $client)));
    }

    /**
     * Report a key or certificate added to the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function keyAdded(Connection $connection, ConnectionKey $key, ?Caller $caller, ClientContext $client): void
    {
        $this->dispatcher->dispatch(new KeyAdded($this->context($connection, $caller, $client), $key->id, $key->use, $key->state, $key->fingerprint, $key->not_after));
    }

    /**
     * Report a key made current, and the key it replaced, if any.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  ?\SineMacula\Laravel\Sso\Models\ConnectionKey  $previous
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function keyMadeCurrent(Connection $connection, ConnectionKey $key, ?ConnectionKey $previous, ?Caller $caller, ClientContext $client): void
    {
        $this->dispatcher->dispatch(new KeyMadeCurrent($this->context($connection, $caller, $client), $key->id, $key->use, $key->fingerprint, $previous?->id));
    }

    /**
     * Report a key retired and removed, given the row as read before the
     * delete.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function keyRetired(Connection $connection, ConnectionKey $key, ?Caller $caller, ClientContext $client): void
    {
        $this->dispatcher->dispatch(new KeyRetired($this->context($connection, $caller, $client), $key->id, $key->use, $key->fingerprint));
    }

    /**
     * Report a key within the expiry threshold or expired; never one without an
     * end of validity.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  int  $thresholdDays
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function keyNearingExpiry(Connection $connection, ConnectionKey $key, int $thresholdDays, ClientContext $client, ?Caller $caller = null): void
    {
        if ($key->not_after === null) {
            return;
        }

        $this->dispatcher->dispatch(new KeyNearingExpiry($this->context($connection, $caller, $client), $key->id, $key->use, $key->fingerprint, $key->not_after, $thresholdDays));
    }

    /**
     * The context of a change to the connection by the caller.
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
