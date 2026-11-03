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
 * `sso:prune`: deletes the authorisation requests, handoff codes, single-use
 * keys, link reservations, pending domain claims and rate limit counters the
 * package no longer needs (SSO-11.11), through `Pruning\Pruner`. Schedule it
 * hourly; it is idempotent and safe to run on several servers at once.
 *
 * It prints one line with the count of each kind and how the run ended. It exits
 * 0 when the run is complete, and when it is incomplete, stopped by the work cap
 * with more eligible, which it says, since the next run goes on; `--drain` goes
 * past the cap. It exits 1 when a kind stopped on an exception, printing what
 * committed before it and naming the kind and the exception by class alone,
 * since a message could carry a value read from the database.
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
            return $this->failed($exception->report);
        } catch (\Throwable $exception) {
            $this->error(sprintf('The prune stopped on %s.', $exception::class));

            return self::FAILURE;
        }

        $this->line(self::summary($report));

        if ($report->status === PruneStatus::INCOMPLETE) {
            $this->warn('More is eligible: the next run goes on, or run sso:prune --drain.');
        }

        return self::SUCCESS;
    }

    /**
     * Print what committed, and what stopped.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\PruneReport  $report
     * @return int
     */
    private function failed(PruneReport $report): int
    {
        $this->line(self::summary($report));

        foreach ($report->failures as $kind => $class) {
            $this->error(sprintf('The prune of %s stopped on %s.', $kind, $class));
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
