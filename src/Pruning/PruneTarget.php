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
 * One kind's prune eligibility at a run's cutoff, and the queries that act on
 * it.
 *
 * Deletes repeat the eligibility, so a row renewed since it was selected stays.
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
     * The next eligible rows after the one given, by keyset on (time, key).
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
     * Split a batch into the units that commit together; reservations split by
     * connection.
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
     * Delete the unit's rows that are still eligible and return the count.
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
     * The kind's target, with the cutoff formatted for its connection.
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
     * Withdraw one connection's reservations, raising its links version.
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
