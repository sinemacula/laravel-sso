<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `sso:check`: runs the boot configuration checks and exits non-zero on a
 * problem.
 *
 * Reads configuration only: no database connection, network request or secret.
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
