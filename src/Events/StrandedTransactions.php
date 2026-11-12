<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\Events\TransactionBeginning;

/**
 * Marks the transaction records a failed commit left behind, so
 * `AfterCommitDispatcher` drops the events queued on them.
 *
 * Laravel 12 keeps a failed outermost commit's records, callbacks and all, for
 * the next commit on the connection; Laravel 13 drops them itself.
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
     * Mark every record the manager holds for the connection as stranded, but
     * for the outermost transaction just begun on it and its savepoints.
     *
     * @param  \Illuminate\Database\Events\TransactionBeginning  $event
     * @param  \Illuminate\Database\DatabaseTransactionsManager  $manager
     * @return void
     */
    public function begun(TransactionBeginning $event, DatabaseTransactionsManager $manager): void
    {
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
