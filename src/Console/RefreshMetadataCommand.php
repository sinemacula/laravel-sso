<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Bus\Dispatcher;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\MetadataSettings;
use SineMacula\Laravel\Sso\Metadata\RefreshConnectionMetadata;
use SineMacula\Laravel\Sso\Metadata\RefreshResult;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `sso:metadata:refresh`: queues a refresh job for every connection due, or
 * runs them inline with `--sync`.
 *
 * Exits 0 whatever the refreshes' outcomes, which their events and logs report.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AsCommand(name: 'sso:metadata:refresh')]
final class RefreshMetadataCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = 'sso:metadata:refresh {--sync : Refresh each due connection in this process instead of queueing it}';

    /** @var string The console command description. */
    protected $description = 'Queue the refresh of every laravel-sso connection whose metadata refresh is due';

    /**
     * Queue or, with `--sync`, run every due refresh and print the counts.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataRefresher  $refresher
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataSettings  $settings
     * @param  \Illuminate\Contracts\Bus\Dispatcher  $bus
     * @return int
     */
    public function handle(MetadataRefresher $refresher, MetadataSettings $settings, Dispatcher $bus): int
    {
        try {
            $line = $this->option('sync') === true ? self::summary($refresher->refreshDue(new ClientContext(null, null))) : self::queued($refresher, $settings, $bus);
        } catch (\Throwable $exception) {
            $this->error(sprintf('The metadata refresh stopped on %s.', $exception::class));

            return self::FAILURE;
        }

        $this->line($line);

        return self::SUCCESS;
    }

    /**
     * Queue a refresh of each connection due, and say how many.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataRefresher  $refresher
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataSettings  $settings
     * @param  \Illuminate\Contracts\Bus\Dispatcher  $bus
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function queued(MetadataRefresher $refresher, MetadataSettings $settings, Dispatcher $bus): string
    {
        $ids = $refresher->dueConnectionIds();

        foreach ($ids as $id) {
            $bus->dispatch(new RefreshConnectionMetadata($id, $settings));
        }

        return sprintf('Metadata refreshes queued: %d', count($ids));
    }

    /**
     * The count of each outcome, on one line.
     *
     * @param  list<\SineMacula\Laravel\Sso\Metadata\RefreshResult>  $results
     * @return string
     */
    private static function summary(array $results): string
    {
        $outcomes = array_map(static fn (RefreshResult $result): string => $result->outcome->value, $results);
        $counts   = array_map(
            static fn (RefreshOutcome $outcome): string => sprintf('%s %d', $outcome->value, count(array_keys($outcomes, $outcome->value, true))),
            RefreshOutcome::cases(),
        );

        return 'Metadata refreshed: ' . implode(', ', $counts);
    }
}
