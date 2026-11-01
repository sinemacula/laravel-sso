<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\RefreshResult;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `sso:metadata:refresh`: refreshes every SAML connection whose scheduled
 * metadata refresh is due (SSO-2.8, SSO-11.12), through
 * `Metadata\MetadataRefresher`. Schedule it every 5 minutes or more often, so a
 * failed refresh is tried again when its backoff ends; it is idempotent and
 * safe to run on several servers at once, each connection claimed by one.
 *
 * It prints one line, the count of each outcome, and nothing of any connection
 * or its metadata: no URL, entity id or certificate. It exits 0 whatever the
 * refreshes' outcomes, which their events and logs report, and 1 only when the
 * run stopped on an exception, which it names by class alone, since a message
 * could carry a value read from the database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AsCommand(name: 'sso:metadata:refresh')]
final class RefreshMetadataCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = 'sso:metadata:refresh';

    /** @var string The console command description. */
    protected $description = 'Refresh every laravel-sso connection whose metadata refresh is due';

    /**
     * Refresh every connection whose refresh is due, and print the count of
     * each outcome.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataRefresher  $refresher
     * @return int
     */
    public function handle(MetadataRefresher $refresher): int
    {
        try {
            $results = $refresher->refreshDue();
        } catch (\Throwable $exception) {
            $this->error(sprintf('The metadata refresh stopped on %s.', $exception::class));

            return self::FAILURE;
        }

        $this->line(self::summary($results));

        return self::SUCCESS;
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
