<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;

/**
 * The guard through which `Auth::sessions()` reaches the stand-in for
 * `laravel-authentication`'s session service (its PR #127), which this package
 * does not install: the facade forwards a call it does not know to the default
 * guard, so a test makes this the default guard and the adapter's call runs as
 * written. It authenticates nobody itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExternalGuard implements Guard
{
    use GuardHelpers;

    /**
     * Constructor.
     *
     * @param  \Tests\Integration\Examples\IntegratingWithLaravelIam\ExternalSessions  $sessions
     */
    public function __construct(

        /** The stand-in for authentication's session service. */
        private readonly ExternalSessions $sessions,
    ) {}

    /**
     * Authentication's session service.
     *
     * @return \Tests\Integration\Examples\IntegratingWithLaravelIam\ExternalSessions
     */
    public function sessions(): ExternalSessions
    {
        return $this->sessions;
    }

    /**
     * Nobody is authenticated through this guard.
     *
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function user(): ?Authenticatable
    {
        return null;
    }

    /**
     * No credentials are valid here.
     *
     * @param  array<array-key, mixed>  $credentials
     * @return bool
     */
    #[\Override]
    public function validate(array $credentials = []): bool
    {
        unset($credentials);

        return false;
    }
}
