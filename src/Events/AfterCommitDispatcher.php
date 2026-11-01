<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
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
 * The connection is the storage connection unless the caller names another,
 * since every package table lives there. No package event implements
 * `ShouldDispatchAfterCommit`, which would wait for the last transaction of any
 * connection instead.
 *
 * The events dispatcher and the transactions manager are resolved from the
 * container on each call, never held: a dispatcher swapped in later (an
 * `Event::fake()` between the write and its commit) receives the event, and the
 * testing traits' manager, which ignores the transaction wrapping each test, is
 * the one consulted. Nothing of one request is kept for the next (SSO-11.2).
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
        $pending = $this->pendingTransaction($connection ?? StorageConnection::resolvedName());

        if ($pending === null) {

            $this->dispatchNow($event);

            return;
        }

        $pending->addCallback(function () use ($event): void {
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

        return $manager->callbackApplicableTransactions()->last(
            static fn (DatabaseTransactionRecord $transaction): bool => $transaction->connection === $connection,
        );
    }
}
