<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config;

/**
 * The registry of configuration checks by subject: the package's own, then each
 * added one in order.
 *
 * Add from a provider's `register()` through `callAfterResolving()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ConfigurationChecks
{
    /**
     * Constructor.
     *
     * @param  array<string, class-string<\SineMacula\Laravel\Sso\Contracts\ConfigurationCheck>>  $checks
     */
    public function __construct(

        /** The checks by subject, in run order. */
        private array $checks,
    ) {}

    /**
     * Add a check under a new subject; the class is resolved only when checks
     * run.
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
