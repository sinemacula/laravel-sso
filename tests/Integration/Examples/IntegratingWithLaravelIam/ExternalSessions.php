<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use Tests\Integration\Examples\IntegratingWithLaravelIam\Contracts\ExternalIdentityLinks;

/**
 * A stand-in for `laravel-authentication`'s external sign-in,
 * `Auth::sessions()->signInExternally()` (its PR #127), which this package does
 * not install: it asks the link contract for the result's connection, issuer
 * and subject, refuses the result as `link_mismatch` unless the answer is
 * exactly the result's link, and otherwise establishes a session, or refuses
 * for the reason a test sets, as authentication's policy would.
 *
 * It keeps its sessions in memory, which is all a test needs. Authentication
 * writes them on the same database connection, inside the adapter's
 * transaction, so they commit or roll back with the redemption.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExternalSessions
{
    /** @var array<string, \Tests\Integration\Examples\IntegratingWithLaravelIam\ExternalResult> Each session established, by its id. */
    private array $sessions = [];

    /** @var ?string Why authentication refuses every sign-in for now, if it does. */
    private ?string $refusal = null;

    /**
     * Sign the person of the result in, or refuse.
     *
     * @param  \Tests\Integration\Examples\IntegratingWithLaravelIam\ExternalResult  $result
     * @return \Tests\Integration\Examples\IntegratingWithLaravelIam\SignInResult
     */
    public function signInExternally(ExternalResult $result): SignInResult
    {
        $linkId = app(ExternalIdentityLinks::class)->find($result->connectionId, $result->issuer, $result->subject);

        if ($linkId === null || $linkId !== $result->linkId) {
            return SignInResult::failed('link_mismatch');
        }

        if ($this->refusal !== null) {
            return SignInResult::failed($this->refusal);
        }

        $sessionId = 'session-' . (count($this->sessions) + 1);

        $this->sessions[$sessionId] = $result;

        return SignInResult::signedIn($sessionId);
    }

    /**
     * Refuse every sign-in for the reason from now on.
     *
     * @param  string  $reason
     * @return void
     */
    public function refuseWith(string $reason): void
    {
        $this->refusal = $reason;
    }

    /**
     * Sign people in again.
     *
     * @return void
     */
    public function accept(): void
    {
        $this->refusal = null;
    }

    /**
     * Each session established, by its id, with the result it was given.
     *
     * @return array<string, \Tests\Integration\Examples\IntegratingWithLaravelIam\ExternalResult>
     */
    public function established(): array
    {
        return $this->sessions;
    }
}
