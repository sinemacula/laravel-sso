<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config;

use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * The configuration checks the `ConfigurationChecker` runs, by subject
 * (SSO-12.3): the package's own (`SsoServiceProvider::CONFIGURATION_CHECKS`),
 * then each one a composing package or the application added, in the order they
 * were added.
 *
 * It is the application's singleton, so a check added once, as the application
 * registers its providers, is run by the boot check, by each worker command as
 * it starts and by `sso:check` alike. Add a check from a service provider's
 * `register()`, through `callAfterResolving()` with this class and a callback
 * calling `add()`, which adds it whichever provider registers first.
 *
 * A subject names one check: one already registered, the package's own
 * included, cannot be added again, so an added check never replaces or shadows
 * another.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ConfigurationChecks
{
    /** @var array<string, class-string<\SineMacula\Laravel\Sso\Contracts\ConfigurationCheck>> The checks, by subject, in the order they run. */
    private array $checks = SsoServiceProvider::CONFIGURATION_CHECKS;

    /**
     * Add a check, to run after every check registered before it.
     *
     * The class is not resolved here: the checker resolves it each time the
     * configuration is checked, before asking whether it applies, and reports
     * one that cannot be built, or is not a `ConfigurationCheck`, as a problem
     * of its subject.
     *
     * @param  string  $subject
     * @param  class-string<\SineMacula\Laravel\Sso\Contracts\ConfigurationCheck>  $class
     * @return void
     *
     * @throws \LogicException
     */
    public function add(string $subject, string $class): void
    {
        if (trim($subject) === '') {
            throw new \LogicException('A configuration check needs a subject.');
        }

        if (array_key_exists($subject, $this->checks)) {
            throw new \LogicException("A configuration check is already registered under [{$subject}].");
        }

        $this->checks[$subject] = $class;
    }

    /**
     * Every check, by subject, in the order they run.
     *
     * @return array<string, class-string<\SineMacula\Laravel\Sso\Contracts\ConfigurationCheck>>
     */
    public function all(): array
    {
        return $this->checks;
    }
}
