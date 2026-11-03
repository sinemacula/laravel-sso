<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Operations;

use Cron\CronExpression;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\BooleanSetting;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The settings of the operations schedule (SSO-11.11, SSO-11.12), read from
 * `sso.operations` on each call (SSO-11.2), each failing closed with an
 * `InvalidArgumentException` naming its key when it is malformed; `[operations]`
 * reports the same at boot.
 *
 * - `cadence.<task>`: when `OperationsSchedule` runs each of `TASKS`, a cron
 *   expression, or `null` or empty to leave it to the application.
 * - `cache_mutexes`: whether each task opts in to Laravel's cache mutexes
 *   (default `false`). Every command is safe without them.
 * - `mutex_minutes`: how long a mutex a dead process left holds, 1 to 1440
 *   minutes (default 60).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OperationsSettings
{
    /** @var array<string, string> Each task's key under `sso.operations.cadence`, and its default cron expression. */
    public const array TASKS = [
        'prune'            => '0 * * * *',
        'domain_recheck'   => '0 * * * *',
        'metadata_refresh' => '*/5 * * * *',
        'expiry_report'    => '0 0 * * *',
    ];

    /** @var int How long a mutex holds when none is configured, in minutes. */
    public const int DEFAULT_MUTEX_MINUTES = 60;

    /** @var int The longest a mutex may hold, in minutes (a day). */
    public const int MAX_MUTEX_MINUTES = 1440;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the settings are read from. */
        private Repository $config,
    ) {}

    /**
     * The cron expression the task runs on, or `null` when it is left to the
     * application.
     *
     * @param  string  $task
     * @return ?string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function cadence(string $task): ?string
    {
        if (!array_key_exists($task, self::TASKS)) {
            throw new \LogicException(sprintf('`%s` is not an operations task.', $task));
        }

        $key     = 'sso.operations.cadence.' . $task;
        $cadence = $this->config->get($key, self::TASKS[$task]);

        if ($cadence === null || $cadence === '') {
            return null;
        }

        if (!is_string($cadence) || !CronExpression::isValidExpression($cadence)) {
            throw new \InvalidArgumentException(sprintf('%s must be a cron expression, or null or empty for none.', $key));
        }

        return $cadence;
    }

    /**
     * Whether each task opts in to Laravel's cache mutexes.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function usesCacheMutexes(): bool
    {
        return BooleanSetting::read($this->config, 'sso.operations.cache_mutexes', false);
    }

    /**
     * How long a mutex a dead process left holds, in minutes.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function mutexMinutes(): int
    {
        return IntegerSetting::read($this->config, 'sso.operations.mutex_minutes', self::DEFAULT_MUTEX_MINUTES, 1, self::MAX_MUTEX_MINUTES);
    }
}
