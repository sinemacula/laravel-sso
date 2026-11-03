<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Sso\Config\IntegerSetting;
use SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice;
use SineMacula\Laravel\Sso\Keys\ExpiringKey;
use SineMacula\Laravel\Sso\Keys\ExpiryReport;
use SineMacula\Laravel\Sso\Keys\ExpiryRun;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `sso:keys:expiring`: lists every key and certificate whose validity is about
 * to end or has ended, and sends the warning of each that has reached a
 * threshold and not yet been warned of it (SSO-2.6, SSO-11.12), through
 * `Keys\ExpiryReport`. Schedule it daily; it is safe to run on several servers
 * at once, and a warning may be sent twice but is never lost.
 *
 * It prints one line per key, `[<expired|expiring>] key <id> (connection <id>,
 * <use>) ends <time>, threshold <days>: <notice>`, whatever was notified before,
 * so a problem nobody has solved stays visible, then the counts. Its output
 * carries identifiers and dates alone, never a key or a certificate. An expired
 * certificate is reported, never enforced, so the exit code does not depend on
 * finding one: it exits 0, unless a warning's dispatch threw, which a later run
 * sends again, or the run stopped on an exception, which it names by class alone,
 * since a message could carry a value read from the database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AsCommand(name: 'sso:keys:expiring')]
final class ExpiringKeysCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = 'sso:keys:expiring {--days= : List what ends within this many days, 1 to 365, rather than within the largest threshold}';

    /** @var string The console command description. */
    protected $description = 'List the laravel-sso keys and certificates nearing expiry, and warn of those that reached a threshold';

    /**
     * Run the report, print each key as it is read, and print the counts.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\ExpiryReport  $report
     * @return int
     */
    public function handle(ExpiryReport $report): int
    {
        try {
            $run = $report->report($this->days(), $this->printEntry(...));
        } catch (\Throwable $exception) {
            $this->error(sprintf('The expiry report stopped on %s.', $exception::class));

            return self::FAILURE;
        }

        $this->line(self::summary($run));

        return $run->hasFailures() ? self::FAILURE : self::SUCCESS;
    }

    /**
     * The days the `--days` option names, or `null` when it is not given.
     *
     * @return ?int
     *
     * @throws \InvalidArgumentException
     */
    private function days(): ?int
    {
        $days = $this->option('days');

        return $days === null ? null : IntegerSetting::from('--days', $days, ExpiryReport::MIN_DAYS, ExpiryReport::MAX_DAYS);
    }

    /**
     * Print the entry, as a warning when it has expired.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\ExpiringKey  $entry
     * @return void
     */
    private function printEntry(ExpiringKey $entry): void
    {
        $line = sprintf(
            '[%s] key %s (connection %s, %s) ends %s, threshold %s: %s',
            $entry->expired ? 'expired' : 'expiring',
            $entry->key->id,
            $entry->key->connectionId,
            $entry->key->use->value,
            $entry->key->notAfter?->utc()->format('Y-m-d\TH:i:s\Z') ?? 'never',
            $entry->thresholdDays                                   ?? 'none',
            $entry->notice->value,
        );

        if ($entry->expired) {
            $this->warn($line);

            return;
        }

        $this->line($line);
    }

    /**
     * The counts, on one line.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\ExpiryRun  $run
     * @return string
     */
    private static function summary(ExpiryRun $run): string
    {
        $notices = array_map(static fn (ExpiryNotice $notice): string => sprintf('%s %d', $notice->value, $run->count($notice)), ExpiryNotice::cases());

        return sprintf('Keys listed: %d, expired %d; warnings: %s', $run->listed, $run->expired, implode(', ', $notices));
    }
}
