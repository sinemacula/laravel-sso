<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;

/**
 * What happens, inside the same transaction, to what a connection has in flight
 * when the connection is disabled, deleted or its trust changes (SSO-2.11,
 * SSO-2.13): every authorisation request through it that has not finished and
 * every handoff code issued through it that has not been redeemed is voided, so
 * none of them completes or is redeemed against the connection as it was.
 *
 * `voidFor()` is called under the connection's row lock, which every completion
 * and redemption takes first (the lock order of `flows.md`), so a completion
 * still going on finds its request voided once it takes the lock, and a
 * redemption finds its code voided. It sets `voided_at` (and `updated_at`) to
 * the clock's now in two statements: on the connection's requests with neither
 * `completed_at` nor `voided_at` set, a request a completion has consumed but
 * not yet finished included, and on its codes with neither `redeemed_at` nor
 * `voided_at` set. A request or code voided before keeps its first `voided_at`;
 * a finished request and a redeemed code are left as they are. Called outside a
 * transaction on the storage connection, it is a `LogicException`, since a void
 * that commits apart from the change could leave the change undone and the
 * flows voided, or the reverse.
 *
 * Its updates cannot see a row inserted since the snapshot of a PostgreSQL
 * `REPEATABLE READ` transaction, so every insert it must void also writes the
 * connection's row: storing an authorisation request
 * (`Flows\AuthorizationRequestService`) and issuing a handoff code
 * (`Handoffs\DatabaseHandoffStore`) each raise the connection's `flows_version`
 * by one under its lock. A change whose snapshot predates either insert then
 * fails to serialise (SQLSTATE `40001`) when it locks the connection, before it
 * voids anything, and never commits with the new request or code left unvoided.
 *
 * It then calls `reservationsVoided()`, which does nothing yet: linking by a
 * verified domain adds there the voiding of the connection's open link
 * reservations (state `reserved`), so a trust change, a disable or a deletion
 * can never leave one to be activated. A database error propagates (SSO-11.4).
 * It holds the clock alone, which keeps nothing of one request for the next
 * (SSO-11.2). It is not final, so a test can observe the calls.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @inheritable
 */
readonly class InFlightVoider
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The clock a void is stamped from. */
        private Clock $clock,
    ) {}

    /**
     * Void the unfinished requests and unredeemed handoff codes of the locked
     * connection, then its open link reservations. Called inside the
     * transaction that changes the connection, with its row locked.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @return void
     *
     * @throws \LogicException
     */
    public function voidFor(Connection $locked): void
    {
        if (DB::connection(StorageConnection::name())->transactionLevel() === 0) {
            throw new \LogicException('In-flight flows are voided inside the transaction that changes their connection.');
        }

        $now = $this->clock->now();

        self::voided(AuthorizationRequest::query(), $locked, 'completed_at', $now);
        self::voided(HandoffCode::query(), $locked, 'redeemed_at', $now);

        $this->reservationsVoided($locked);
    }

    /**
     * Void the open link reservations of the locked connection. Called by
     * `voidFor()` once its requests and codes are voided.
     *
     * Nothing reserves a link yet, so it does nothing: linking by a verified
     * domain adds here the voiding of the connection's reserved links, under
     * the same lock and in the same transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @return void
     *
     * @SuppressWarnings("php:S1172")
     */
    protected function reservationsVoided(Connection $locked): void
    {
        // Nothing reserves a link yet
    }

    /**
     * Set `voided_at` and `updated_at` to the instant on the connection's rows
     * of the query whose column of the end and `voided_at` are both unset.
     *
     * @template TModel of \SineMacula\Laravel\Sso\Models\SsoModel
     *
     * @param  \Illuminate\Database\Eloquent\Builder<TModel>  $query
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  string  $ended
     * @param  \DateTimeInterface  $now
     * @return void
     */
    private static function voided(Builder $query, Connection $locked, string $ended, \DateTimeInterface $now): void
    {
        $stamp = UtcDateTime::format($query->getModel(), $now);

        $query->where('connection_id', $locked->id)
            ->whereNull($ended)
            ->whereNull('voided_at')
            ->update(['voided_at' => $stamp, 'updated_at' => $stamp]);
    }
}
