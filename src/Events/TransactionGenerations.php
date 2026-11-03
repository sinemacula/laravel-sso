<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Illuminate\Database\Events\TransactionBeginning;

/**
 * Counts the outermost transactions begun on each database connection, so an
 * after-commit callback can tell whether the transaction it was queued in is
 * the one now committing (SSO-10.5).
 *
 * Laravel 12 does not tell its transactions manager when an outermost commit
 * fails, so the callbacks waiting on that transaction stay pending and run on
 * the next outermost commit on the connection, which on a long-running worker
 * can be another request's. A transaction that commits runs its callbacks
 * before the next one begins, so a callback that runs under a later generation
 * than the one it was queued in can only belong to a transaction whose commit
 * failed, and `AfterCommitDispatcher` drops it. Laravel 13 drops such callbacks
 * itself, so none arrives late there and nothing changes.
 *
 * Only an outermost begin counts, seen by the `TransactionBeginning` listener
 * the service provider registers once: a savepoint is part of the transaction
 * it sits in. A connection whose events dispatcher does not deliver the event
 * keeps its count, and a late callback on it is dispatched as Laravel would.
 *
 * The count is kept by connection name for the life of the process, so this is
 * bound as a singleton and resolved when the provider boots, never scoped: a
 * late callback can run in a later request or job than the one that queued it,
 * and a count started afresh there could reach the generation it was queued in
 * again. It holds no request's data, only a name and a number, as a
 * connection's own transaction level does (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TransactionGenerations
{
    /** @var array<string, int> The outermost transactions begun so far, by connection name. */
    private array $generations = [];

    /**
     * Count the transaction begun when it is the outermost on its connection.
     *
     * @param  \Illuminate\Database\Events\TransactionBeginning  $event
     * @return void
     */
    public function begun(TransactionBeginning $event): void
    {
        if ($event->connection->transactionLevel() !== 1) {
            return;
        }

        $this->generations[$event->connectionName] = $this->current($event->connectionName) + 1;
    }

    /**
     * The number of outermost transactions begun so far on the connection, `0`
     * before the first.
     *
     * @param  string  $connection
     * @return int
     */
    public function current(string $connection): int
    {
        return $this->generations[$connection] ?? 0;
    }
}
