<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;

/**
 * Voids what a connection has in flight when it is disabled, deleted or its
 * trust changes, inside the transaction that makes the change.
 *
 * Not final, so a test can observe the calls.
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
     * Void unfinished requests, unredeemed codes and open reservations, and
     * raise the trust version; `$spared` is an unknown-`kid` refetch's request.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  ?string  $spared
     * @return void
     *
     * @throws \LogicException
     */
    public function voidFor(Connection $locked, ?string $spared = null): void
    {
        if (DB::connection(StorageConnection::name())->transactionLevel() === 0) {
            throw new \LogicException('In-flight flows are voided inside the transaction that changes their connection.');
        }

        $now = $this->clock->now();

        self::voided($spared === null ? AuthorizationRequest::query() : AuthorizationRequest::query()->whereKeyNot($spared), $locked, 'completed_at', $now);
        self::voided(HandoffCode::query(), $locked, 'redeemed_at', $now);

        $locked->increment('trust_version');

        $this->reservationsVoided($locked);
    }

    /**
     * Void the open link reservations of the locked connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @return void
     */
    protected function reservationsVoided(Connection $locked): void
    {
        ReservationWithdrawal::ofConnection($locked);
    }

    /**
     * Stamp `voided_at` on the connection's rows not yet ended or voided.
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
