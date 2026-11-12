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
 * Deletes expired rows the package no longer needs, in short batches.
 *
 * Call outside any transaction; several servers may run it at once.
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

        /** The sanitising logger. */
        private LoggerInterface $logger,
    ) {}

    /**
     * Prune every kind at one instant; a drain ignores the per-kind work cap.
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

        $report     = $this->reportOf($now, $sweeps);
        $logFailure = $this->log($report);

        if ($report->failures !== [] || $logFailure !== null) {
            throw new PruneFailedException($report, self::firstFailure($sweeps) ?? $logFailure, $logFailure);
        }

        return $report;
    }

    /**
     * Delete batches of one kind until none is left or the cap is reached.
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
     * Delete a batch unit by unit, counting each as it commits.
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
     * The first sweep exception, for the failure to chain.
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
     * Build the run's report from each kind's sweep.
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
     * The run's status from its incomplete and failed kinds.
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
     * Log the run's one line, returning what the logger threw, if anything.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\PruneReport  $report
     * @return ?\Throwable
     */
    private function log(PruneReport $report): ?\Throwable
    {
        $level = match ($report->status) {
            PruneStatus::COMPLETE   => LogLevel::INFO,
            PruneStatus::INCOMPLETE => LogLevel::WARNING,
            PruneStatus::FAILED     => LogLevel::ERROR,
        };

        try {
            $this->logger->log($level, self::LOG_MESSAGE, $report->jsonSerialize());
        } catch (\Throwable $exception) {
            return $exception;
        }

        return null;
    }
}
