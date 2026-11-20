<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\SamlString;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `sso:check`: runs the boot configuration checks and exits non-zero on a
 * problem.
 *
 * Reads configuration only: no database connection, network request or secret.
 * While SAML is on, it also fails where the SAML library's string validation
 * refuses characters above U+00FF, as under PCRE2 10.45 to 10.47.
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
     * Constructor.
     *
     * @param  string  $probe
     */
    public function __construct(

        /** The character the SAML library's string validation must accept. */
        private readonly string $probe = "\u{100}",
    ) {
        parent::__construct();
    }

    /**
     * Check the configuration and report each problem, or that there is none.
     *
     * @param  \SineMacula\Laravel\Sso\Config\ConfigurationChecker  $checker
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return int
     */
    public function handle(ConfigurationChecker $checker, Repository $config): int
    {
        $failed = false;
        $report = $checker->report();

        if (Features::requested($config, Feature::SAML2) && !SamlString::isValid($this->probe)) {
            $report['saml2'][] = sprintf('The SAML library refuses characters above U+00FF under PCRE %s; use PCRE2 10.48 or later.', PCRE_VERSION);
        }

        foreach ($report as $subject => $problems) {

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
