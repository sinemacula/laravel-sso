<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Freshness;

use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The example application's record of when each session last authenticated
 * (SSO-2.12), standing in for the sessions table its sign-in writes: by session
 * id, the identity signed in on it and the Unix time it authenticated, read
 * back only for that identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SignInTimes
{
    /** @var array<string, array{identity: \SineMacula\Laravel\Sso\Identities\IdentityReference, authenticated_at: int}> Each session's sign-in, by its id. */
    private array $sessions = [];

    /**
     * Record that the identity authenticated on the session at the time given.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  int  $authenticatedAt
     * @return void
     */
    public function record(IdentityReference $identity, string $sessionId, int $authenticatedAt): void
    {
        $this->sessions[$sessionId] = ['identity' => $identity, 'authenticated_at' => $authenticatedAt];
    }

    /**
     * When the identity last authenticated on the session, or `null` when the
     * session is unknown or another identity's.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @return ?int
     */
    public function authenticatedAt(IdentityReference $identity, string $sessionId): ?int
    {
        $session = $this->sessions[$sessionId] ?? null;

        return $session !== null && $session['identity']->is($identity) ? $session['authenticated_at'] : null;
    }
}
