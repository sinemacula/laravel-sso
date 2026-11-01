<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Domains\RecheckEntry;
use SineMacula\Laravel\Sso\Domains\RecheckReport;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `sso:domains:recheck`: checks every verified domain's TXT record again
 * (SSO-3.3, SSO-11.12), through `Domains\DomainRechecker`. Schedule it, hourly
 * for instance; it is idempotent and safe to run on several servers at once.
 *
 * It prints one line per domain whose check did more than confirm it,
 * `[<outcome>] <domain> (connection <id>)`, then the count of each outcome. It
 * exits non-zero when a lookup failed, so a resolver that cannot answer is
 * noticed, and when the run stopped on an exception, which it names by class
 * alone: an exception's message could carry a value read from the database or
 * the DNS, and the command prints neither a token nor a record.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AsCommand(name: 'sso:domains:recheck')]
final class RecheckDomainsCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = 'sso:domains:recheck';

    /** @var string The console command description. */
    protected $description = 'Check every verified laravel-sso domain\'s DNS TXT record again';

    /**
     * Recheck every verified domain and report what changed.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\DomainRechecker  $rechecker
     * @return int
     */
    public function handle(DomainRechecker $rechecker): int
    {
        try {
            $report = $rechecker->recheckAll();
        } catch (\Throwable $exception) {
            $this->error(sprintf('The domain recheck stopped on %s.', $exception::class));

            return self::FAILURE;
        }

        foreach ($report->entries as $entry) {
            $this->printEntry($entry);
        }

        $this->line(self::summary($report));

        return $report->hasLookupFailures() ? self::FAILURE : self::SUCCESS;
    }

    /**
     * Print the entry, unless its domain was only confirmed or left alone.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\RecheckEntry  $entry
     * @return void
     */
    private function printEntry(RecheckEntry $entry): void
    {
        if ($entry->outcome === RecheckOutcome::CONFIRMED || $entry->outcome === RecheckOutcome::SKIPPED) {
            return;
        }

        $line = sprintf('[%s] %s (connection %s)', $entry->outcome->value, $entry->domain, $entry->connectionId);

        if ($entry->outcome->isFailure()) {
            $this->warn($line);

            return;
        }

        $this->line($line);
    }

    /**
     * The count of each outcome, on one line.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\RecheckReport  $report
     * @return string
     */
    private static function summary(RecheckReport $report): string
    {
        $counts = array_map(static fn (RecheckOutcome $outcome): string => sprintf('%s %d', $outcome->value, $report->count($outcome)), RecheckOutcome::cases());

        return 'Domains rechecked: ' . implode(', ', $counts);
    }
}
