<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Illuminate\Container\Container;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\Events\TransactionBeginning;

/**
 * Marks the transaction records a failed commit left behind, so
 * `AfterCommitDispatcher` drops the events queued on them (SSO-10.5).
 *
 * Laravel 12 does not tell its transactions manager when an outermost commit
 * fails, so the records of that transaction stay in the manager, with their
 * callbacks, and run on the next outermost commit on the connection, which on a
 * long-running worker can be another request's. When an outermost transaction
 * begins, its connection had none open, so every record the manager still holds
 * for it is stranded, but for the one just begun and any savepoint inside it. A
 * committing transaction is not among them: the manager removes its records
 * before running their callbacks, so a transaction begun from one of those
 * callbacks leaves them alone. Laravel 13 drops such records itself.
 *
 * A beginning whose event is not delivered marks nothing, and a callback left
 * on such a record is dispatched as Laravel would. The marks are weak, so a
 * record is forgotten with its transaction. This is a singleton, resolved when
 * the provider boots, since the listener and the dispatcher must share it; it
 * holds no request's data (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StrandedTransactions
{
    /** @var \WeakMap<\Illuminate\Database\DatabaseTransactionRecord, true> The records a failed commit left behind. */
    private \WeakMap $stranded;

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->stranded = new \WeakMap;
    }

    /**
     * Mark every record held for the connection as stranded when an outermost
     * transaction begins on it, but for that transaction's own.
     *
     * @param  \Illuminate\Database\Events\TransactionBeginning  $event
     * @return void
     */
    public function begun(TransactionBeginning $event): void
    {
        // The current container: an Octane sandbox's manager when one serves.
        $container = Container::getInstance();
        $manager   = $container->bound('db.transactions') ? $container->make('db.transactions') : null;

        if ($event->connection->transactionLevel() !== 1 || !$manager instanceof DatabaseTransactionsManager) {
            return;
        }

        $name = $event->connectionName;

        // The raw collections: the testing manager's view skips by position.
        $pending = $manager->getPendingTransactions();
        $begun   = $pending->last(static fn (DatabaseTransactionRecord $record): bool => $record->connection === $name);

        foreach ($pending->concat($manager->getCommittedTransactions()) as $record) {

            if ($record->connection !== $name || self::isWithin($record, $begun)) {
                continue;
            }

            $this->stranded[$record] = true;
        }
    }

    /**
     * Whether a failed commit left the record behind.
     *
     * @param  \Illuminate\Database\DatabaseTransactionRecord  $record
     * @return bool
     */
    public function isStranded(DatabaseTransactionRecord $record): bool
    {
        return $this->stranded[$record] ?? false;
    }

    /**
     * Whether the record is the transaction given or a savepoint inside it.
     *
     * @param  \Illuminate\Database\DatabaseTransactionRecord  $record
     * @param  ?\Illuminate\Database\DatabaseTransactionRecord  $transaction
     * @return bool
     */
    private static function isWithin(DatabaseTransactionRecord $record, ?DatabaseTransactionRecord $transaction): bool
    {
        for ($current = $record; $current !== null; $current = $current->parent) {
            if ($current === $transaction) {
                return true;
            }
        }

        return false;
    }
}
