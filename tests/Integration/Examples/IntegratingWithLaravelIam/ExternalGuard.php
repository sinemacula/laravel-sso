<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;

/**
 * The default guard, which Laravel's `Auth` forwards `sessions()` to; it
 * authenticates nobody itself.
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
