<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

/**
 * Configuration check contract: the checks of one part of the package's
 * configuration, run at boot and by `sso:check` (SSO-12.3).
 *
 * A check is registered under a subject: the package's own in
 * `SsoServiceProvider::CONFIGURATION_CHECKS`, and a composing package's or the
 * application's through `Config\ConfigurationChecks::add()`. It is resolved
 * from the container each time the configuration is checked, so it reads the
 * configuration as it is then. It applies only to what is enabled: the checker
 * asks `applies()` first and skips a check that does not apply, so a feature
 * that is off is never checked and never fails a boot. It is built before
 * `applies()` is asked, so building it must not depend on what it covers being
 * on. An added check that covers the package's use applies only while
 * `Config\Features::isInUse()`, so it never fails the boot of an application
 * with the package off.
 *
 * Each check reads configuration only: it opens no database connection, makes
 * no network request and names no secret or configured value in its message,
 * only the key and what the key must be.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ConfigurationCheck
{
    /**
     * Whether what the check covers is enabled. It must not throw: a switch it
     * cannot read counts as on (see `Config\Features::requested()`), so the
     * settings it would enable are checked rather than skipped.
     *
     * @return bool
     */
    public function applies(): bool;

    /**
     * The checks, each a closure that throws an exception (an
     * `InvalidArgumentException` for a malformed setting, a `LogicException`
     * for a missing one, a `RuntimeException` for a missing extension or
     * library) whose message names the problem, and returns otherwise. Every
     * closure runs, so one run reports every problem.
     *
     * @return list<\Closure(): mixed>
     */
    public function checks(): array;
}
