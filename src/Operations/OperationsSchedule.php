<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Operations;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;

/**
 * Registers the package's maintenance commands on the application's schedule.
 *
 * No cache mutex by default: every command is safe on several servers at once,
 * so a stale mutex can never suppress maintenance.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OperationsSchedule
{
    /** @var array<string, string> The command each task runs. */
    public const array COMMANDS = [
        'prune'            => 'sso:prune',
        'domain_recheck'   => 'sso:domains:recheck',
        'metadata_refresh' => 'sso:metadata:refresh',
        'expiry_report'    => 'sso:keys:expiring',
    ];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Sso\Operations\OperationsSettings  $settings
     */
    public function __construct(

        /** The configuration that says whether the package is in use. */
        private Repository $config,

        /** The cadences and the mutex switch, read on each call. */
        private OperationsSettings $settings,
    ) {}

    /**
     * Add each task with a cadence; nothing while the package is not in use.
     *
     * A malformed setting is reported and skipped, so it stops neither the rest
     * of the schedule nor any console command; `sso:check` names it.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return void
     */
    public function register(Schedule $schedule): void
    {
        if (!Features::isInUse($this->config)) {
            return;
        }

        $mutexMinutes = $this->mutexMinutes();

        foreach (self::COMMANDS as $task => $command) {

            try {
                $cadence = $this->settings->cadence($task);
            } catch (\InvalidArgumentException $exception) {
                report($exception);

                continue;
            }

            if ($cadence === null) {
                continue;
            }

            $event = $schedule->command($command)->cron($cadence);

            if ($mutexMinutes === null) {
                continue;
            }

            $event->withoutOverlapping($mutexMinutes)->onOneServer();
        }
    }

    /**
     * How long a mutex holds, or `null` for none, which a malformed setting
     * falls back to since every task is safe on several servers.
     *
     * @return ?int
     */
    private function mutexMinutes(): ?int
    {
        try {
            return $this->settings->usesCacheMutexes() ? $this->settings->mutexMinutes() : null;
        } catch (\InvalidArgumentException $exception) {
            report($exception);

            return null;
        }
    }
}
