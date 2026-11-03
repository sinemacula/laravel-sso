<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Operations;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * `[operations]`: the operations schedule's settings, while the package is in
 * use (SSO-11.11, SSO-11.12), each read as `OperationsSettings` reads it, so
 * the check and the schedule judge it the same way.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OperationsCheck implements ConfigurationCheck
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration checked. */
        private Repository $config,
    ) {}

    /**
     * The schedule is checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse();
    }

    /**
     * Each task's cadence, the switch and how long a mutex holds.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $settings = new OperationsSettings($this->config);

        $checks = array_map(
            static fn (string $task): \Closure => static fn (): ?string => $settings->cadence($task),
            array_keys(OperationsSettings::TASKS),
        );

        $checks[] = static fn (): bool => $settings->usesCacheMutexes();
        $checks[] = static fn (): int => $settings->mutexMinutes();

        return $checks;
    }
}
