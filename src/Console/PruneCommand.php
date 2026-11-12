<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneStatus;
use SineMacula\Laravel\Sso\Pruning\PruneFailedException;
use SineMacula\Laravel\Sso\Pruning\Pruner;
use SineMacula\Laravel\Sso\Pruning\PruneReport;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `sso:prune`: deletes the expired rows the package no longer needs.
 *
 * Exceptions are named by class alone, since a message could carry a stored
 * value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AsCommand(name: 'sso:prune')]
final class PruneCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = 'sso:prune {--drain : Look at every row eligible now, whatever the work cap}';

    /** @var string The console command description. */
    protected $description = 'Delete the expired laravel-sso rows the package no longer needs';

    /**
     * Run the clean-up and say how it ended.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Pruner  $pruner
     * @return int
     */
    public function handle(Pruner $pruner): int
    {
        try {
            $report = $pruner->run($this->option('drain') === true);
        } catch (PruneFailedException $exception) {
            return $this->failed($exception);
        } catch (\Throwable $exception) {
            $this->error(sprintf('The prune stopped on %s.', $exception::class));

            return self::FAILURE;
        }

        $this->printReport($report);

        return self::SUCCESS;
    }

    /**
     * Print what committed, every kind that failed, and a hint when incomplete.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\PruneReport  $report
     * @return void
     */
    private function printReport(PruneReport $report): void
    {
        $this->line(self::summary($report));

        foreach ($report->failures as $kind => $class) {
            $this->error(sprintf('The prune of %s stopped on %s.', $kind, $class));
        }

        if ($report->status !== PruneStatus::INCOMPLETE) {
            return;
        }

        $this->warn('More is eligible: the next run goes on, or run sso:prune --drain.');
    }

    /**
     * Print the failed run's report and any logger failure.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\PruneFailedException  $exception
     * @return int
     */
    private function failed(PruneFailedException $exception): int
    {
        $this->printReport($exception->report);

        if ($exception->logFailure !== null) {
            $this->error(sprintf('The prune\'s log line failed on %s.', $exception->logFailure::class));
        }

        return self::FAILURE;
    }

    /**
     * The count of each kind and how the run ended, on one line.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\PruneReport  $report
     * @return string
     */
    private static function summary(PruneReport $report): string
    {
        $counts = array_map(static fn (string $kind, int $count): string => "{$kind} {$count}", array_keys($report->deleted), $report->deleted);

        return sprintf('Pruned (%s): %s', $report->status->value, implode(', ', $counts));
    }
}
