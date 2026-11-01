<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `sso:check`: runs the configuration checks the web boot runs (SSO-12.3) and
 * exits non-zero on a problem, for deploy pipelines and readiness probes, and
 * for the console, where the check runs only as a worker or scheduler command
 * starts, so that a misconfigured application can still be inspected and fixed.
 *
 * Every registered check is reported under its subject: `[<subject>] OK`,
 * `[<subject>] not enabled` for one that does not apply, or one line per
 * problem, `[<subject>] <message>`. The command reads configuration only: it
 * opens no database connection, makes no network request and prints no secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AsCommand(name: 'sso:check')]
final class CheckConfigurationCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = 'sso:check';

    /** @var string The console command description. */
    protected $description = 'Check the configuration of every enabled laravel-sso feature';

    /**
     * Check the configuration and report each problem, or that there is none.
     *
     * @param  \SineMacula\Laravel\Sso\Config\ConfigurationChecker  $checker
     * @return int
     */
    public function handle(ConfigurationChecker $checker): int
    {
        $failed = false;

        foreach ($checker->report() as $subject => $problems) {

            if ($problems === null) {
                $this->line("[{$subject}] not enabled");

                continue;
            }

            if ($problems === []) {
                $this->info("[{$subject}] OK");

                continue;
            }

            foreach ($problems as $problem) {
                $this->error("[{$subject}] {$problem}");
            }

            $failed = true;
        }

        return $failed ? self::FAILURE : self::SUCCESS;
    }
}
