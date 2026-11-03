<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Pruning;

use Carbon\CarbonImmutable;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneKind;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneStatus;

/**
 * Deletes what the package no longer needs (SSO-11.11): authorisation requests
 * and handoff codes past their expiry and the retention, and expired single-use
 * keys, link reservations, pending domain claims and rate limit counters, the
 * last on their own connection. `Pruning\PruneTarget` holds the eligibility of
 * each. `sso:prune` runs it, and several servers may at once.
 *
 * A run reads the clock once, so every kind is judged by one instant. Each kind
 * then takes its turn: at most `batch_size` primary keys are selected on the
 * write connection, by keyset, and deleted with the eligibility repeated. The
 * scan moves on by what it selected, so a batch another server has already
 * deleted does not end it, and it counts what was deleted, never what was
 * selected. Each batch commits by itself, a batch of reservations one
 * connection at a time, and each is counted as it commits, so a run holds no
 * long transaction and reports what it committed however it ends.
 *
 * A kind stops at `max_rows_per_kind` rows looked at, so every kind gets its
 * turn however large another's backlog: the report says `incomplete` when more
 * was eligible, and the next run goes on where this one would have. A drain
 * takes no cap, and ends on the rows eligible at its one instant.
 *
 * An exception stops the kind it came from and the others still take their
 * turn. The run then logs its one summary line and throws
 * `PruneFailedException`, holding the report of what committed; a run begun
 * again finds what is left, since what it would delete is still eligible.
 *
 * Grace is not what makes this safe. A completion or a redemption delayed past
 * a row's retention is refused by its own expiry checks, and a locked recheck
 * that finds the row gone refuses as well.
 *
 * It refuses to run inside a transaction on either connection it uses (a
 * `LogicException`), since a caller's transaction would turn every short batch
 * into one long one. It dispatches no event, being housekeeping, and logs one
 * line per run: the outcome, the duration, the counts, and for a kind that
 * failed its exception's class alone. It holds the settings, the clock and the
 * logger, none of which keeps anything of one run for the next (SSO-11.2).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Pruner
{
    /** @var string The name of the run's one log line. */
    public const string LOG_MESSAGE = 'sso.prune.finished';

    /** @var string Why a run refuses to run inside a transaction. */
    private const string IN_TRANSACTION = 'A prune runs outside any transaction on the storage and rate limit connections, so that each batch commits by itself.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\PruneSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \Psr\Log\LoggerInterface  $logger
     */
    public function __construct(

        /** The retention, the batch and the work cap. */
        private PruneSettings $settings,

        /** The clock each run reads its one instant from. */
        private Clock $clock,

        /** The sanitising logger the run's one line goes to. */
        private LoggerInterface $logger,
    ) {}

    /**
     * Give every kind its turn at one instant and report what was deleted; a
     * drain looks at every row eligible at that instant, whatever the work cap.
     *
     * @param  bool  $drain
     * @return \SineMacula\Laravel\Sso\Pruning\PruneReport
     *
     * @throws \SineMacula\Laravel\Sso\Pruning\PruneFailedException
     */
    public function run(bool $drain = false): PruneReport
    {
        StorageConnection::assertNoTransactionOnAny(self::IN_TRANSACTION);

        $batch = $this->settings->batchSize();
        $cap   = $drain ? null : $this->settings->maxRowsPerKind();
        $now   = $this->clock->now();
        $kept  = $now->subSeconds($this->settings->retentionSeconds());

        $sweeps = [];

        foreach (PruneTarget::all($now, $kept) as $target) {
            $sweeps[$target->kind->value] = self::sweep($target, $batch, $cap);
        }

        $report = $this->reportOf($now, $sweeps);

        $this->log($report);

        if ($report->failures !== []) {
            throw new PruneFailedException($report, self::firstFailure($sweeps));
        }

        return $report;
    }

    /**
     * One kind's turn: delete batch after batch until nothing more is eligible
     * or the work cap is reached. Each transaction of a batch is counted as it
     * commits, so an exception ends the turn with the count of what has.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\PruneTarget  $target
     * @param  int  $batch
     * @param  ?int  $cap
     * @return \SineMacula\Laravel\Sso\Pruning\PruneSweep
     */
    private static function sweep(PruneTarget $target, int $batch, ?int $cap): PruneSweep
    {
        $deleted = 0;
        $looked  = 0;
        $after   = null;

        try {

            do {

                $limit = $cap === null ? $batch : min($batch, $cap - $looked);
                $found = $target->candidates($after, $limit);

                self::deleteBatch($target, $found, $deleted);

                $looked += count($found);
                $after = end($found) ?: $after;
                $more  = count($found) === $limit;
            } while ($more && ($cap === null || $looked < $cap));

            return new PruneSweep($deleted, $more && $target->candidates($after, 1) !== []);
        } catch (\Throwable $exception) {
            return new PruneSweep($deleted, false, $exception);
        }
    }

    /**
     * Delete a batch one committed transaction at a time, adding each one's
     * count as it commits, so that an exception from a later one leaves the
     * count of those before it.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\PruneTarget  $target
     * @param  list<\SineMacula\Laravel\Sso\Pruning\PruneCandidate>  $found
     * @param  int  $deleted
     * @return void
     *
     * @throws \Throwable
     */
    private static function deleteBatch(PruneTarget $target, array $found, int &$deleted): void
    {
        foreach ($target->units($found) as $unit) {
            $deleted += $target->delete($unit);
        }
    }

    /**
     * The first exception of the sweeps, for the failure to chain.
     *
     * @param  array<string, \SineMacula\Laravel\Sso\Pruning\PruneSweep>  $sweeps
     * @return ?\Throwable
     */
    private static function firstFailure(array $sweeps): ?\Throwable
    {
        foreach ($sweeps as $sweep) {
            if ($sweep->failure !== null) {
                return $sweep->failure;
            }
        }

        return null;
    }

    /**
     * The report of the run begun at the instant, from each kind's turn.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @param  array<string, \SineMacula\Laravel\Sso\Pruning\PruneSweep>  $sweeps
     * @return \SineMacula\Laravel\Sso\Pruning\PruneReport
     */
    private function reportOf(CarbonImmutable $now, array $sweeps): PruneReport
    {
        $failed     = array_filter($sweeps, static fn (PruneSweep $sweep): bool => $sweep->failure !== null);
        $failures   = array_map(static fn (PruneSweep $sweep): string => ($sweep->failure ?? new \LogicException)::class, $failed);
        $incomplete = array_map(PruneKind::from(...), array_keys(array_filter($sweeps, static fn (PruneSweep $sweep): bool => $sweep->incomplete)));

        return new PruneReport(
            self::statusOf($incomplete, $failures),
            $now,
            (int) max(0, $now->diffInMilliseconds($this->clock->now())),
            array_map(static fn (PruneSweep $sweep): int => $sweep->deleted, $sweeps),
            $incomplete,
            $failures,
        );
    }

    /**
     * How a run with those kinds incomplete and failed ended.
     *
     * @param  list<\SineMacula\Laravel\Sso\Pruning\Enums\PruneKind>  $incomplete
     * @param  array<string, class-string<\Throwable>>  $failures
     * @return \SineMacula\Laravel\Sso\Pruning\Enums\PruneStatus
     */
    private static function statusOf(array $incomplete, array $failures): PruneStatus
    {
        if ($failures !== []) {
            return PruneStatus::FAILED;
        }

        return $incomplete === [] ? PruneStatus::COMPLETE : PruneStatus::INCOMPLETE;
    }

    /**
     * Log the run's one line: an error when it failed, a warning when it is
     * incomplete, and for information otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\PruneReport  $report
     * @return void
     */
    private function log(PruneReport $report): void
    {
        $level = match ($report->status) {
            PruneStatus::COMPLETE   => LogLevel::INFO,
            PruneStatus::INCOMPLETE => LogLevel::WARNING,
            PruneStatus::FAILED     => LogLevel::ERROR,
        };

        $this->logger->log($level, self::LOG_MESSAGE, $report->jsonSerialize());
    }
}
