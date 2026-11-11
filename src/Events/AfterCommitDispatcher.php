<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Dispatches the package's events once the writes that caused them have
 * committed (SSO-10.5): at once when their connection has no open transaction,
 * on the commit of the innermost transaction open on it otherwise, and never
 * when that transaction, or a savepoint it sits in, is rolled back. A
 * transaction open on another connection neither delays nor cancels the event,
 * since the writes were not made in it.
 *
 * An event waits only for the transaction it was dispatched in. Laravel 12
 * leaves the records of an outermost transaction whose commit failed pending,
 * to run their callbacks on the next outermost commit on the connection,
 * perhaps in another request; so each callback holds its record and dispatches
 * nothing once `StrandedTransactions` has marked it. A record such a
 * transaction left is found only while the connection has a transaction open,
 * so an event dispatched outside one is dispatched at once. Laravel 13 drops
 * those records itself, and nothing changes there.
 *
 * The connection is the storage connection unless the caller names another,
 * since every package table lives there. No package event implements
 * `ShouldDispatchAfterCommit`, which would wait for the last transaction of any
 * connection instead.
 *
 * The events dispatcher, the transactions manager and the database manager are
 * resolved from the container on each call, never held: a dispatcher swapped in
 * later (an `Event::fake()` between the write and its commit) receives the
 * event, and the testing traits' manager, which ignores the transaction
 * wrapping each test, is the one consulted. Nothing of one request is kept for
 * the next (SSO-11.2).
 *
 * Events report only: nothing that must happen for security depends on a
 * listener, which is what the synchronous contracts are for. A listener's
 * exception propagates as it does from Laravel's dispatcher, from the dispatch
 * or from the commit that ran it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AfterCommitDispatcher
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the dispatcher and the transactions manager are resolved from on each call. */
        private Container $container,
    ) {}

    /**
     * Dispatch the event once the writes made on the connection have committed:
     * the storage connection when none is named.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @param  ?string  $connection
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function dispatch(SsoEvent $event, ?string $connection = null): void
    {
        $name    = $connection ?? StorageConnection::resolvedName();
        $pending = $this->pendingTransaction($name);

        if ($pending === null) {

            $this->dispatchNow($event);

            return;
        }

        $stranded = $this->container->make(StrandedTransactions::class);

        $pending->addCallback(function () use ($event, $stranded, $pending): void {

            if ($stranded->isStranded($pending)) {
                return;
            }

            $this->dispatchNow($event);
        });
    }

    /**
     * Dispatch the event at once, whatever transaction is open.
     *
     * This is for the unlinked-result event alone (SSO-8.6), which must reach
     * its listeners synchronously, before any handoff is issued, so one can
     * provision the identity inside the flow. Every other event goes through
     * `dispatch()`.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @return void
     */
    public function dispatchNow(SsoEvent $event): void
    {
        $this->container->make(Dispatcher::class)->dispatch($event);
    }

    /**
     * The innermost transaction open on the connection whose commit callbacks
     * apply, or `null` when there is none or no transactions manager is bound.
     * A record found while the connection has no transaction open was left by a
     * failed commit, and is not one.
     *
     * @param  string  $connection
     * @return ?\Illuminate\Database\DatabaseTransactionRecord
     */
    private function pendingTransaction(string $connection): ?DatabaseTransactionRecord
    {
        $manager = $this->container->bound('db.transactions') ? $this->container->make('db.transactions') : null;

        if (!$manager instanceof DatabaseTransactionsManager) {
            return null;
        }

        $pending = $manager->callbackApplicableTransactions()->last(
            static fn (DatabaseTransactionRecord $transaction): bool => $transaction->connection === $connection,
        );

        return $pending !== null && $this->hasOpenTransaction($connection) ? $pending : null;
    }

    /**
     * Whether the connection has a transaction open.
     *
     * @param  string  $connection
     * @return bool
     */
    private function hasOpenTransaction(string $connection): bool
    {
        return $this->container->make(ConnectionResolverInterface::class)->connection($connection)->transactionLevel() > 0;
    }
}
