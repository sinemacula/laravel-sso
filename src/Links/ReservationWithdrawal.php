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
 * Deletes open link reservations in the transaction of a change that takes away
 * what they stand on.
 *
 * Call with the connection's row locked, and the domain's when one is named.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReservationWithdrawal
{
    /** @var int Attempts in all at `expired()` when a deadlock rolled it back. */
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
     * Delete every reservation bound to the locked domain claim, and answer how
     * many.
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
     * Delete the reserved ones of the locked rows given, and answer how many.
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
     * In its own short transaction, delete the named reservations still
     * reserved and expired by the cutoff, and answer how many.
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
     * Raise the links version when anything was deleted, so a stale PostgreSQL
     * snapshot fails to serialise; answer the count.
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
