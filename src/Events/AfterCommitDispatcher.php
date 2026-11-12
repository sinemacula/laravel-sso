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
 * Dispatches the package's events once the innermost transaction open on their
 * connection commits, and never when it rolls back.
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

        /** Resolved from on each call, so a dispatcher faked later still receives. */
        private Container $container,
    ) {}

    /**
     * Dispatch the event once the connection's writes commit; the storage
     * connection when none is named.
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
     * Dispatch the event at once; only for the unlinked-result event, whose
     * listeners provision the identity before any handoff is issued.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @return void
     */
    public function dispatchNow(SsoEvent $event): void
    {
        $this->container->make(Dispatcher::class)->dispatch($event);
    }

    /**
     * The innermost transaction on the connection whose commit callbacks apply;
     * a record found with no transaction open was left by a failed commit.
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
