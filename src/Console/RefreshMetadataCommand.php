<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Bus\Dispatcher;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\MetadataSettings;
use SineMacula\Laravel\Sso\Metadata\RefreshConnectionMetadata;
use SineMacula\Laravel\Sso\Metadata\RefreshResult;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `sso:metadata:refresh`: sends the refresh of every SAML connection whose
 * scheduled metadata refresh is due to the queue (SSO-2.8, SSO-11.12), one
 * `Metadata\RefreshConnectionMetadata` job per connection on the queue
 * connection and queue `sso.metadata.queue` names, so a deployment sends large
 * federation metadata to workers sized for it. With `--sync` it refreshes them
 * in the command instead, one after the other, through
 * `Metadata\MetadataRefresher::refreshDue()`. Schedule it every 5 minutes or
 * more often, so a failed refresh is tried again when its backoff ends; it is
 * idempotent and safe to run on several servers at once, each connection
 * claimed by one refresh, and a job that finds its connection no longer due
 * does nothing.
 *
 * It prints one line, the number of refreshes queued, or with `--sync` the
 * count of each outcome, and nothing of any connection or its metadata: no URL,
 * entity id or certificate. It exits 0 whatever the refreshes' outcomes, which
 * their events and logs report, and 1 only when the run stopped on an
 * exception, which it names by class alone, since a message could carry a value
 * read from the database.
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
     * Queue a refresh of every connection whose refresh is due and print how
     * many, or refresh them here with `--sync` and print the count of each
     * outcome.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataRefresher  $refresher
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataSettings  $settings
     * @param  \Illuminate\Contracts\Bus\Dispatcher  $bus
     * @return int
     */
    public function handle(MetadataRefresher $refresher, MetadataSettings $settings, Dispatcher $bus): int
    {
        try {
            $line = $this->option('sync') === true ? self::summary($refresher->refreshDue()) : self::queued($refresher, $settings, $bus);
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
