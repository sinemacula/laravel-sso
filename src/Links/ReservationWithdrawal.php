<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\RetriedTransaction;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\Link;

/**
 * Withdraws open link reservations inside the transaction of a change that
 * takes away what they stand on (SSO-2.13, SSO-3.3, SSO-8.8): a connection
 * disabled or deleted, a protocol trust change, a change to its linking
 * settings, a domain's linking suspended, removed or lapsed, or the identity's
 * scope widening.
 *
 * Each is called with the connection's row locked, and the domain's when one is
 * named, in the package's lock order. It deletes by the reservation's own
 * state, so an active or suspended link is never touched and a row expired
 * already goes too. There is no tombstone: a handoff's reservation id names
 * nothing once its row is gone, and a later reservation has another id. A
 * deletion raises the connection's links version, as a reservation's creation
 * does: a PostgreSQL `REPEATABLE READ` change whose snapshot predates a
 * reservation fails to serialise when it locks the row, rather than miss it.
 *
 * Pruning has no change to be part of, so `expired()` is its own short
 * transaction: it locks the connection, deletes only the rows named that are
 * still reserved and past the cutoff, and raises the version when it deleted
 * any. An activation that holds the connection's lock finishes first, and the
 * row it made active is no longer reserved; one that comes after finds no
 * reservation to activate.
 *
 * It holds nothing (SSO-11.2). A database error propagates (SSO-11.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReservationWithdrawal
{
    /** @var int How many times `expired()` is tried in all when a deadlock rolled it back. */
    private const int ATTEMPTS = 3;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Delete every reservation of the locked connection, and answer how many.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @return int
     */
    public static function ofConnection(Connection $locked): int
    {
        $deleted = Link::query()->useWritePdo()
            ->where('connection_id', $locked->id)
            ->where('state', LinkState::RESERVED->value)
            ->toBase()
            ->delete();

        return self::raised($locked->id, $deleted);
    }

    /**
     * Delete every reservation bound to the locked domain claim of the locked
     * connection, and answer how many.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @return int
     */
    public static function ofDomain(Connection $locked, Domain $domain): int
    {
        $deleted = Link::query()->useWritePdo()
            ->where('connection_id', $locked->id)
            ->where('reservation_domain_id', $domain->id)
            ->where('state', LinkState::RESERVED->value)
            ->toBase()
            ->delete();

        return self::raised($locked->id, $deleted);
    }

    /**
     * Delete the reserved rows given, already locked, of the locked connection,
     * and answer how many: those of an identity whose scope widened. A row of
     * another state is left.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<int, \SineMacula\Laravel\Sso\Models\Link>  $rows
     * @return int
     */
    public static function ofRows(Connection $locked, array $rows): int
    {
        $deleted = 0;

        foreach ($rows as $row) {

            if ($row->state !== LinkState::RESERVED) {
                continue;
            }

            $row->delete();
            $deleted++;
        }

        return self::raised($locked->id, $deleted);
    }

    /**
     * In a short transaction of its own, lock the connection and delete those
     * of the reservations named that are still reserved and expired by the
     * cutoff, as the links table stores times, and answer how many. A
     * connection gone has no version to raise, and its rows are deleted just
     * the same.
     *
     * @param  string  $connectionId
     * @param  non-empty-list<string>  $ids
     * @param  string  $cutoff
     * @return int
     *
     * @throws \Throwable
     */
    public static function expired(string $connectionId, array $ids, string $cutoff): int
    {
        return RetriedTransaction::run(DB::connection(StorageConnection::name()), static function () use ($connectionId, $ids, $cutoff): int {

            Connection::query()->useWritePdo()->whereKey($connectionId)->lockForUpdate()->first();

            $deleted = Link::query()->useWritePdo()
                ->where('connection_id', $connectionId)
                ->whereKey($ids)
                ->where('state', LinkState::RESERVED->value)
                ->where('reservation_expires_at', '<=', $cutoff)
                ->toBase()
                ->delete();

            return self::raised($connectionId, $deleted);
        }, self::ATTEMPTS);
    }

    /**
     * Raise the connection's links version when anything was deleted, and
     * answer how much was.
     *
     * @param  string  $connectionId
     * @param  int  $deleted
     * @return int
     */
    private static function raised(string $connectionId, int $deleted): int
    {
        if ($deleted > 0) {
            Connection::query()->useWritePdo()->whereKey($connectionId)->increment('links_version');
        }

        return $deleted;
    }
}
