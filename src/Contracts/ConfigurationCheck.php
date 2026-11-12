<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

/**
 * The checks of one part of the package's configuration, run at boot and by
 * `sso:check`.
 *
 * Read configuration only: no database, no network, and no value in a message.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ConfigurationCheck
{
    /**
     * Whether what the check covers is enabled; never throw, and treat an
     * unreadable switch as on.
     *
     * @return bool
     */
    public function applies(): bool;

    /**
     * Closures that each throw on a problem; every one runs, so one run reports
     * every problem.
     *
     * @return list<\Closure(): mixed>
     */
    public function checks(): array;
}
