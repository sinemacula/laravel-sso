<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Exceptions;

/**
 * Thrown at boot when the configuration of an enabled feature has a problem
 * (SSO-12.3), listing every problem the checks found, each as
 * `[<subject>] <message>`. A message names the setting and what it must be,
 * never a configured value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidConfigurationException extends \LogicException
{
    /** @var list<string> The problems found, each prefixed with its subject. */
    private array $problems = [];

    /**
     * The exception for the problems found.
     *
     * @param  non-empty-list<string>  $problems
     * @return self
     */
    public static function withProblems(array $problems): self
    {
        $message = "laravel-sso is misconfigured; `php artisan sso:check` lists the same problems:\n- " . implode("\n- ", $problems);

        $exception           = new self($message);
        $exception->problems = $problems;

        return $exception;
    }

    /**
     * The problems found, each prefixed with its subject.
     *
     * @return list<string>
     */
    public function problems(): array
    {
        return $this->problems;
    }
}
