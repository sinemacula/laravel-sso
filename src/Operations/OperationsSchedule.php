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
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function register(Schedule $schedule): void
    {
        if (!Features::isInUse($this->config)) {
            return;
        }

        $mutexes = $this->settings->usesCacheMutexes();

        foreach (self::COMMANDS as $task => $command) {

            $cadence = $this->settings->cadence($task);

            if ($cadence === null) {
                continue;
            }

            $event = $schedule->command($command)->cron($cadence);

            if (!$mutexes) {
                continue;
            }

            $event->withoutOverlapping($this->settings->mutexMinutes())->onOneServer();
        }
    }
}
