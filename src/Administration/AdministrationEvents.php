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
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;

/**
 * Reports the changes the management helpers make to connections, keys and
 * certificates (SSO-10.3): each method builds the event's context through the
 * one projection (`Events\EventContexts`), from the connection's id, tenant and
 * protocol and the acting identity the application passed, and hands the event
 * to `Events\AfterCommitDispatcher`, so it reaches listeners once the change
 * commits and never when it rolls back (SSO-10.5).
 *
 * A helper calls it inside the transaction that made the change, after the
 * write, once per change: never for a refused or a no-op call, which changed
 * nothing. `connectionUpdated()` takes the names of the settings that changed,
 * never their values, and reports nothing when none did. A key's events carry
 * its id, use and fingerprint, never its private key.
 *
 * It holds the projection and the dispatcher, both of which read the clock, the
 * request and the transaction from the container on each call, so nothing of
 * one request is kept for the next (SSO-11.2).
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
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function connectionCreated(Connection $connection, ?ActingIdentity $actor): void
    {
        $this->dispatcher->dispatch(new ConnectionCreated($this->context($connection, $actor)));
    }

    /**
     * Report the settings of a connection that changed, by name; nothing when
     * none did.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  list<string>  $changedSettings
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function connectionUpdated(Connection $connection, array $changedSettings, ?ActingIdentity $actor): void
    {
        $names = array_values(array_unique($changedSettings));

        if ($names === []) {
            return;
        }

        $this->dispatcher->dispatch(new ConnectionUpdated($this->context($connection, $actor), $names));
    }

    /**
     * Report a connection enabled.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function connectionEnabled(Connection $connection, ?ActingIdentity $actor): void
    {
        $this->dispatcher->dispatch(new ConnectionEnabled($this->context($connection, $actor)));
    }

    /**
     * Report a connection disabled.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function connectionDisabled(Connection $connection, ?ActingIdentity $actor): void
    {
        $this->dispatcher->dispatch(new ConnectionDisabled($this->context($connection, $actor)));
    }

    /**
     * Report a connection deleted. Called with the connection as it was read
     * before the delete, in the delete's transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function connectionDeleted(Connection $connection, ?ActingIdentity $actor): void
    {
        $this->dispatcher->dispatch(new ConnectionDeleted($this->context($connection, $actor)));
    }

    /**
     * Report a key or certificate added to the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function keyAdded(Connection $connection, ConnectionKey $key, ?ActingIdentity $actor): void
    {
        $this->dispatcher->dispatch(new KeyAdded($this->context($connection, $actor), $key->id, $key->use, $key->state, $key->fingerprint, $key->not_after));
    }

    /**
     * Report a key made current, and the key it replaced, now retiring, when
     * there was one.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  ?\SineMacula\Laravel\Sso\Models\ConnectionKey  $previous
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function keyMadeCurrent(Connection $connection, ConnectionKey $key, ?ConnectionKey $previous, ?ActingIdentity $actor): void
    {
        $this->dispatcher->dispatch(new KeyMadeCurrent($this->context($connection, $actor), $key->id, $key->use, $key->fingerprint, $previous?->id));
    }

    /**
     * Report a key or certificate retired and removed. Called with the row as
     * it was read before the delete, in the delete's transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function keyRetired(Connection $connection, ConnectionKey $key, ?ActingIdentity $actor): void
    {
        $this->dispatcher->dispatch(new KeyRetired($this->context($connection, $actor), $key->id, $key->use, $key->fingerprint));
    }

    /**
     * Report a key or certificate whose validity ends within the warning, or
     * has ended. A key with no end of validity is never reported.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function keyNearingExpiry(Connection $connection, ConnectionKey $key, ?ActingIdentity $actor = null): void
    {
        if ($key->not_after === null) {
            return;
        }

        $this->dispatcher->dispatch(new KeyNearingExpiry($this->context($connection, $actor), $key->id, $key->use, $key->fingerprint, $key->not_after));
    }

    /**
     * The context of a change to the connection by the acting identity.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    private function context(Connection $connection, ?ActingIdentity $actor): EventContext
    {
        return $this->contexts->make(
            connectionId: $connection->id,
            tenantId: $connection->tenant_id,
            protocol: $connection->protocol,
            actingIdentityMorphClass: $actor?->type,
            actingIdentityId: $actor?->id,
        );
    }
}
