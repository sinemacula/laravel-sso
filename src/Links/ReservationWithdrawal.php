<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

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
 * It holds nothing (SSO-11.2). A database error propagates (SSO-11.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReservationWithdrawal
{
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

        return self::raised($locked, $deleted);
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

        return self::raised($locked, $deleted);
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

        return self::raised($locked, $deleted);
    }

    /**
     * Raise the connection's links version when anything was deleted, and
     * answer how much was.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  int  $deleted
     * @return int
     */
    private static function raised(Connection $locked, int $deleted): int
    {
        if ($deleted > 0) {
            Connection::query()->useWritePdo()->whereKey($locked->id)->increment('links_version');
        }

        return $deleted;
    }
}
