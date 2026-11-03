<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Operations;

use Illuminate\Console\Scheduling\Schedule;
use SineMacula\Laravel\Sso\Config\Features;

/**
 * Registers the package's operations on the application's schedule (SSO-11.11,
 * SSO-11.12), in one call from `withSchedule()` or a service provider:
 *
 * | Task               | Command                | Default cadence |
 * | ------------------ | ---------------------- | --------------- |
 * | `prune`            | `sso:prune`            | hourly          |
 * | `domain_recheck`   | `sso:domains:recheck`  | hourly          |
 * | `metadata_refresh` | `sso:metadata:refresh` | every 5 minutes |
 * | `expiry_report`    | `sso:keys:expiring`    | daily           |
 *
 * Every command is safe to run on several servers at once, by what it does in
 * the database, so by default each runs on every server and no task it
 * registers reads or writes a cache: a stale mutex can never suppress
 * maintenance (SSO-11.6). `schedule:run` is the framework's own: on Laravel 13
 * it reads its pause signal from the default cache before any task, unless the
 * application calls `Schedule::withoutInterruptionPolling()`, which this class
 * leaves to it as a choice for every task the application has.
 * `sso.operations.cache_mutexes` opts in to `withoutOverlapping()` and
 * `onOneServer()`, which save work and guarantee nothing. They use the
 * schedule's own cache store, which `Schedule::useCache()` chooses for every
 * task of the application, so the package leaves that choice alone.
 *
 * It registers nothing while the package is not in use, when the tables a
 * command reads may not exist. It holds the settings, which keep nothing
 * (SSO-11.2).
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
     * @param  \SineMacula\Laravel\Sso\Operations\OperationsSettings  $settings
     */
    public function __construct(

        /** The cadences and the mutex switch, read on each call. */
        private OperationsSettings $settings,
    ) {}

    /**
     * Add each task with a cadence to the schedule.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function register(Schedule $schedule): void
    {
        if (!Features::isInUse()) {
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
