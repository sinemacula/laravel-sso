<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Pruning;

use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Models\RateLimit;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Models\SsoModel;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneKind;

/**
 * One kind's eligibility at one run's cutoff, the one place it is written
 * (SSO-11.11), and the two statements that act on it:
 *
 * | Kind                     | Eligible when                                              |
 * | ------------------------ | ---------------------------------------------------------- |
 * | `authorization_requests` | `expires_at` <= now - retention, whatever its state        |
 * | `handoff_codes`          | `expires_at` <= now - retention, whatever its state        |
 * | `single_use_keys`        | `expires_at` <= now                                        |
 * | `reservations`           | `state` = reserved and `reservation_expires_at` <= now     |
 * | `pending_claims`         | `state` = pending and `pending_expires_at` <= now          |
 * | `rate_limits`            | `window_ends_at` <= now, on the counters' connection       |
 *
 * `candidates()` selects primary keys on the write connection, in the order of
 * the kind's index, by keyset on (time, key), never by offset. `delete()` names
 * those keys and repeats the eligibility, so a row renewed, activated or
 * verified since it was selected stands, and answers the rows affected, never
 * the rows selected. What it is given is one of `units()`, the rows that commit
 * together. A batch of reservations is a unit for each of its connections,
 * ascending, each deleted through `Links\ReservationWithdrawal::expired()` in a
 * short transaction of its own, since it raises the connection's links version;
 * a batch of any other kind is one unit and one statement, tried again when the
 * database rolled it back as a deadlock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PruneTarget
{
    /** @var int How many times a statement a deadlock rolled back is tried in all. */
    private const int ATTEMPTS = 3;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @param  \SineMacula\Laravel\Sso\Models\SsoModel  $model
     * @param  string  $column
     * @param  string  $cutoff
     * @param  ?string  $state
     */
    public function __construct(

        /** What this target deletes. */
        public PruneKind $kind,

        /** The model naming the table and the connection. */
        private SsoModel $model,

        /** The time column the row is judged by. */
        private string $column,

        /** The cutoff, as the model's connection stores times. */
        private string $cutoff,

        /** The state the row must be in, when the kind has one. */
        private ?string $state = null,
    ) {}

    /**
     * Every kind at the run's cutoffs, in the order a run takes them.
     *
     * @param  \DateTimeInterface  $now
     * @param  \DateTimeInterface  $retained
     * @return list<self>
     */
    public static function all(\DateTimeInterface $now, \DateTimeInterface $retained): array
    {
        return [
            self::of(PruneKind::AUTHORIZATION_REQUESTS, new AuthorizationRequest, 'expires_at', $retained),
            self::of(PruneKind::HANDOFF_CODES, new HandoffCode, 'expires_at', $retained),
            self::of(PruneKind::SINGLE_USE_KEYS, new SingleUseKey, 'expires_at', $now),
            self::of(PruneKind::RESERVATIONS, new Link, 'reservation_expires_at', $now, LinkState::RESERVED->value),
            self::of(PruneKind::PENDING_CLAIMS, new Domain, 'pending_expires_at', $now, DomainState::PENDING->value),
            self::of(PruneKind::RATE_LIMITS, new RateLimit, 'window_ends_at', $now),
        ];
    }

    /**
     * The next eligible rows after the one given, in the order of the kind's
     * index.
     *
     * @param  ?\SineMacula\Laravel\Sso\Pruning\PruneCandidate  $after
     * @param  int  $limit
     * @return list<\SineMacula\Laravel\Sso\Pruning\PruneCandidate>
     */
    public function candidates(?PruneCandidate $after, int $limit): array
    {
        $key     = $this->model->getKeyName();
        $columns = [$key, $this->column];
        $linked  = $this->kind === PruneKind::RESERVATIONS;

        if ($linked) {
            $columns[] = 'connection_id';
        }

        $rows = $this->eligible()
            ->select($columns)
            ->when($after !== null, fn (Builder $query): Builder => $this->continuing($query, $after))
            ->orderBy($this->column)
            ->orderBy($key)
            ->limit($limit)
            ->get();

        $candidates = [];

        foreach ($rows as $row) {
            $candidates[] = new PruneCandidate($row->{$key}, $row->{$this->column}, $linked ? $row->connection_id : null);
        }

        return $candidates;
    }

    /**
     * The batch split into what commits together, in the order it is deleted:
     * so that a failure part of the way through a batch costs only the count of
     * what did not commit.
     *
     * @param  list<\SineMacula\Laravel\Sso\Pruning\PruneCandidate>  $candidates
     * @return list<non-empty-list<\SineMacula\Laravel\Sso\Pruning\PruneCandidate>>
     */
    public function units(array $candidates): array
    {
        if ($this->kind !== PruneKind::RESERVATIONS) {
            return $candidates === [] ? [] : [$candidates];
        }

        $units = [];

        // A connection's id is a ULID, so as an array key it stays a string.
        foreach ($candidates as $candidate) {
            $units[(string) $candidate->connectionId][] = $candidate;
        }

        ksort($units, SORT_STRING);

        return array_values($units);
    }

    /**
     * Delete those of the rows of one unit that are still eligible, and answer
     * how many went.
     *
     * @param  non-empty-list<\SineMacula\Laravel\Sso\Pruning\PruneCandidate>  $candidates
     * @return int
     *
     * @throws \Throwable
     */
    public function delete(array $candidates): int
    {
        if ($this->kind === PruneKind::RESERVATIONS) {
            return $this->withdraw($candidates);
        }

        $keys = array_map(static fn (PruneCandidate $candidate): int|string => $candidate->key, $candidates);

        return $this->model->getConnection()->transaction(
            fn (): int => $this->eligible()->whereIn($this->model->getKeyName(), $keys)->delete(),
            self::ATTEMPTS,
        );
    }

    /**
     * The target of the kind, with the cutoff as its model's connection stores
     * times.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @param  \SineMacula\Laravel\Sso\Models\SsoModel  $model
     * @param  string  $column
     * @param  \DateTimeInterface  $cutoff
     * @param  ?string  $state
     * @return self
     */
    private static function of(PruneKind $kind, SsoModel $model, string $column, \DateTimeInterface $cutoff, ?string $state = null): self
    {
        return new self($kind, $model, $column, UtcDateTime::format($model, $cutoff), $state);
    }

    /**
     * The kind's eligibility, on the write connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function eligible(): Builder
    {
        return $this->model->newQuery()->useWritePdo()->toBase()
            ->where($this->column, '<=', $this->cutoff)
            ->when($this->state !== null, fn (Builder $query): Builder => $query->where('state', $this->state));
    }

    /**
     * Continue the query after the row given.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  ?\SineMacula\Laravel\Sso\Pruning\PruneCandidate  $after
     * @return \Illuminate\Database\Query\Builder
     */
    private function continuing(Builder $query, ?PruneCandidate $after): Builder
    {
        return $query->where(function (Builder $keyset) use ($after): void {
            $keyset->where($this->column, '>', $after?->time)
                ->orWhere(function (Builder $tie) use ($after): void {
                    $tie->where($this->column, $after?->time)->where($this->model->getKeyName(), '>', $after?->key);
                });
        });
    }

    /**
     * Withdraw the reservations of one connection, and answer how many went.
     *
     * @param  non-empty-list<\SineMacula\Laravel\Sso\Pruning\PruneCandidate>  $candidates
     * @return int
     *
     * @throws \Throwable
     */
    private function withdraw(array $candidates): int
    {
        $keys = array_map(static fn (PruneCandidate $candidate): string => (string) $candidate->key, $candidates);

        return ReservationWithdrawal::expired((string) $candidates[0]->connectionId, $keys, $this->cutoff);
    }
}
