<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;
use SineMacula\Laravel\Sso\Exceptions\InvalidConfigurationException;

/**
 * Runs the registered configuration checks (SSO-12.3): at boot, and as a worker
 * or scheduler command starts, where any problem stops the application or the
 * command with an `InvalidConfigurationException`, and in `sso:check`, which
 * lists them.
 *
 * Each check is resolved from the container when the configuration is checked,
 * never before, so registering a check costs nothing until then, and a check
 * that cannot be resolved, or is not a `ConfigurationCheck`, is itself a
 * problem rather than a check skipped. A check that does not apply (what it
 * covers is off) is not run.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfigurationChecker
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  array<string, class-string<\SineMacula\Laravel\Sso\Contracts\ConfigurationCheck>>  $checks
     */
    public function __construct(

        /** The container each check is resolved from. */
        private Container $container,

        /** The checks, by the subject their problems are reported under. */
        private array $checks,
    ) {}

    /**
     * What each check found, by subject: `null` for a check that does not
     * apply, otherwise its problems, `[]` for none.
     *
     * @return array<string, ?list<string>>
     */
    public function report(): array
    {
        $report = [];

        foreach ($this->checks as $subject => $class) {
            $report[$subject] = $this->problemsOf($class);
        }

        return $report;
    }

    /**
     * Every problem found, each prefixed with its subject.
     *
     * @return list<string>
     */
    public function problems(): array
    {
        $problems = [];

        foreach ($this->report() as $subject => $found) {
            foreach ($found ?? [] as $problem) {
                $problems[] = "[{$subject}] {$problem}";
            }
        }

        return $problems;
    }

    /**
     * Fail when any check found a problem.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Exceptions\InvalidConfigurationException
     */
    public function assertValid(): void
    {
        $problems = $this->problems();

        if ($problems !== []) {
            throw InvalidConfigurationException::withProblems($problems);
        }
    }

    /**
     * The problems the check found, or `null` when it does not apply.
     *
     * @param  string  $class
     * @return ?list<string>
     */
    private function problemsOf(string $class): ?array
    {
        $check = $this->resolve($class);

        if (!$check instanceof ConfigurationCheck) {
            return [$check];
        }

        return $check->applies() ? self::run($check) : null;
    }

    /**
     * The check the class names, or the problem that stops it being used: it
     * cannot be built, or it is not a check.
     *
     * @param  string  $class
     * @return \SineMacula\Laravel\Sso\Contracts\ConfigurationCheck|string
     */
    private function resolve(string $class): ConfigurationCheck|string
    {
        try {
            $check = $this->container->make($class);
        } catch (\Exception $exception) {
            return $exception->getMessage();
        }

        return $check instanceof ConfigurationCheck ? $check : sprintf('[%s] is not a %s.', $class, ConfigurationCheck::class);
    }

    /**
     * Run every one of the check's checks, and return the problem each that
     * failed found, in order.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\ConfigurationCheck  $check
     * @return list<string>
     */
    private static function run(ConfigurationCheck $check): array
    {
        $problems = [];

        foreach ($check->checks() as $closure) {
            try {
                $closure();
            } catch (\Exception $exception) {
                $problems[] = $exception->getMessage();
            }
        }

        return $problems;
    }
}
