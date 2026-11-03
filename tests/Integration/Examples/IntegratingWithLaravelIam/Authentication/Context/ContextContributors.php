<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Context;

/**
 * A stand-in for `laravel-authentication`'s real `Context\ContextContributors`,
 * which this package does not install, with the exact signatures of its
 * `register()` and `registered()`
 * (`docs/guides/integrating-with-laravel-iam.md`): a contributor is registered
 * under a namespace of a lower-case letter and then up to 31 lower-case
 * letters, digits or underscores, never `authentication`, and once; anything
 * else is a `LogicException`, as the sibling's is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ContextContributors
{
    /** @var string What a namespace is. */
    private const string NAMESPACE_PATTERN = '/^[a-z][a-z0-9_]{0,31}$/D';

    /** @var string The sibling's own namespace, which no contributor takes. */
    private const string OWN_NAMESPACE = 'authentication';

    /** @var array<string, string> Each contributor's class, by its namespace. */
    private array $contributors = [];

    /**
     * Register the contributor under the namespace.
     *
     * @param  string  $namespace
     * @param  string  $contributor
     * @return void
     *
     * @throws \LogicException
     */
    public function register(string $namespace, string $contributor): void
    {
        if ($namespace === self::OWN_NAMESPACE || preg_match(self::NAMESPACE_PATTERN, $namespace) !== 1) {
            throw new \LogicException(sprintf('An authentication context contributor cannot be registered under [%s].', $namespace));
        }

        if (array_key_exists($namespace, $this->contributors)) {
            throw new \LogicException(sprintf('An authentication context contributor is already registered under [%s]: %s.', $namespace, $this->contributors[$namespace]));
        }

        $this->contributors[$namespace] = $contributor;
    }

    /**
     * Each contributor's class, by its namespace, in the order registered.
     *
     * @return array<string, string>
     */
    public function registered(): array
    {
        return $this->contributors;
    }
}
