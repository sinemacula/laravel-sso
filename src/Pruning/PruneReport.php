<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Pruning;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneKind;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneStatus;

/**
 * What one run of `Pruning\Pruner` did, as counts, kinds and class names only.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PruneReport implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneStatus  $status
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $durationMilliseconds
     * @param  array<string, int>  $deleted
     * @param  list<\SineMacula\Laravel\Sso\Pruning\Enums\PruneKind>  $incomplete
     * @param  array<string, class-string<\Throwable>>  $failures
     */
    public function __construct(

        /** How the run ended. */
        public PruneStatus $status,

        /** The one instant every row was judged by. */
        public CarbonImmutable $now,

        /** How long the run took, in milliseconds. */
        public int $durationMilliseconds,

        /** The rows each kind deleted, by the kind's value, in run order. */
        public array $deleted,

        /** The kinds the work cap stopped with more eligible. */
        public array $incomplete = [],

        /** The class of the exception that stopped each kind, by the kind's value. */
        public array $failures = [],
    ) {}

    /**
     * How many rows the kind deleted.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @return int
     */
    public function deleted(PruneKind $kind): int
    {
        return $this->deleted[$kind->value] ?? 0;
    }

    /**
     * How many rows the run deleted in all.
     *
     * @return int
     */
    public function total(): int
    {
        return array_sum($this->deleted);
    }

    /**
     * Whether every kind reached the end of what was eligible.
     *
     * @return bool
     */
    public function isComplete(): bool
    {
        return $this->status === PruneStatus::COMPLETE;
    }

    /**
     * The log line's context, with snake_case keys and the instant in UTC.
     *
     * @return array{outcome: string, now: string, duration_ms: int, deleted: array<string, int>, incomplete: list<string>, failures: array<string, class-string<\Throwable>>}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'outcome'     => $this->status->value,
            'now'         => $this->now->utc()->format('Y-m-d\TH:i:s\Z'),
            'duration_ms' => $this->durationMilliseconds,
            'deleted'     => $this->deleted,
            'incomplete'  => array_map(static fn (PruneKind $kind): string => $kind->value, $this->incomplete),
            'failures'    => $this->failures,
        ];
    }
}
