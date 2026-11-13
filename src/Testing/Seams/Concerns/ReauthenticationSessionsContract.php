<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Seams\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * What every `Contracts\ReauthenticationSessions` must guarantee, as tests: use
 * it in a test case of the binding and implement the methods it declares.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait ReauthenticationSessionsContract
{
    /**
     * The identity's live session is signed in; a revoked one, another
     * identity's, and the session asked for another identity are not.
     *
     * @return void
     */
    public function testReauthenticationSessionsStandOnlyForTheIdentitysLiveSession(): void
    {
        [$identity, $other] = $this->reauthenticationIdentities();
        [$ids]              = $this->reauthenticationFixture();

        $sessions   = $this->reauthenticationSessions();
        $connection = $this->reauthenticationConnection();
        $app        = $this->reauthenticationApplication();
        $standing   = static fn (IdentityReference $who, string $session): SessionStanding => $sessions->standing($who, $session, $app, $connection);

        Assert::assertSame(SessionStanding::SIGNED_IN, $standing($identity, $ids['live']), 'The identity\'s live session must be signed in.');
        Assert::assertSame(SessionStanding::NOT_SIGNED_IN, $standing($identity, $ids['revoked']), 'A revoked session must not be signed in.');
        Assert::assertSame(SessionStanding::NOT_SIGNED_IN, $standing($identity, $ids['others']), 'Another identity\'s session must not be signed in.');
        Assert::assertSame(SessionStanding::NOT_SIGNED_IN, $standing($other, $ids['live']), 'A session asked for another identity must not be signed in.');
    }

    /**
     * Inside a transaction on the storage connection, the live session stands
     * under its own link alone, not another of its identity's, and the others
     * under none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReauthenticationSessionsLockASessionUnderItsExactLink(): void
    {
        [$identity]    = $this->reauthenticationIdentities();
        [$ids, $links] = $this->reauthenticationFixture();

        $sessions   = $this->reauthenticationSessions();
        $connection = $this->reauthenticationConnection();
        $app        = $this->reauthenticationApplication();

        $answers = DB::connection(StorageConnection::name())->transaction(static fn (): array => [
            $sessions->lockedStanding($identity, $ids['live'], $app, $connection, $links['live']),
            $sessions->lockedStanding($identity, $ids['live'], $app, $connection, $links['revoked']),
            $sessions->lockedStanding($identity, $ids['revoked'], $app, $connection, $links['live']),
            $sessions->lockedStanding($identity, $ids['others'], $app, $connection, $links['others']),
        ]);

        Assert::assertSame(SessionStanding::SIGNED_IN, $answers[0], 'The live session must stand under its own link.');
        Assert::assertSame(SessionStanding::NOT_SIGNED_IN, $answers[1], 'A session must not stand under another link of its identity.');
        Assert::assertSame(SessionStanding::NOT_SIGNED_IN, $answers[2], 'A revoked session must not stand.');
        Assert::assertSame(SessionStanding::NOT_SIGNED_IN, $answers[3], 'Another identity\'s session must not stand.');
    }

    /**
     * A renewal after the locked standing moves the session named to a later
     * provider time, never back to an earlier one, and no other session, of its
     * identity or another's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReauthenticationSessionsRenewOnlyTheSessionNamedForward(): void
    {
        [$identity]    = $this->reauthenticationIdentities();
        [$ids, $links] = $this->reauthenticationFixture();

        $before  = $this->sessionAuthenticatedAt($ids['live']);
        $others  = $this->sessionAuthenticatedAt($ids['others']);
        $sibling = $this->sessionAuthenticatedAt($ids['revoked']);
        $later   = $before->addMinutes(5);

        $this->renewInTransaction($identity, $ids['live'], $links['live'], $later);

        Assert::assertSame($later->getTimestamp(), $this->sessionAuthenticatedAt($ids['live'])->getTimestamp(), 'A later provider time must renew the session.');
        Assert::assertSame($others->getTimestamp(), $this->sessionAuthenticatedAt($ids['others'])->getTimestamp(), 'A renewal must not move another identity\'s session.');
        Assert::assertSame($sibling->getTimestamp(), $this->sessionAuthenticatedAt($ids['revoked'])->getTimestamp(), 'A renewal must not move another session of the identity.');

        $this->renewInTransaction($identity, $ids['live'], $links['live'], $before->subMinutes(5));

        Assert::assertSame($later->getTimestamp(), $this->sessionAuthenticatedAt($ids['live'])->getTimestamp(), 'An earlier provider time must not move the session back.');
    }

    /**
     * Write a renewal the binding recorded rather than wrote, inside the
     * transaction that asked for it; nothing for one that writes at once.
     *
     * @param  string  $sessionId
     * @return void
     */
    protected function completeRenewal(string $sessionId): void
    {
        unset($sessionId);
    }

    /**
     * The binding under test.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions
     */
    abstract protected function reauthenticationSessions(): ReauthenticationSessions;

    /**
     * The connection the sessions are signed in through.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SsoConnection
     */
    abstract protected function reauthenticationConnection(): SsoConnection;

    /**
     * The application the sessions are for.
     *
     * @return string
     */
    abstract protected function reauthenticationApplication(): string;

    /**
     * Two identities that can sign in through the connection.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Identities\IdentityReference, 1: \SineMacula\Laravel\Sso\Identities\IdentityReference}
     */
    abstract protected function reauthenticationIdentities(): array;

    /**
     * Sign the identity in for the application through the connection, under a
     * new link of its own on each call, authenticated at the time given; the
     * session's id and the link's.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @return array{0: string, 1: string}
     */
    abstract protected function signInForReauthentication(IdentityReference $identity, CarbonImmutable $authenticatedAt): array;

    /**
     * End the session.
     *
     * @param  string  $sessionId
     * @return void
     */
    abstract protected function revokeReauthenticationSession(string $sessionId): void;

    /**
     * When the session last authenticated, as stored.
     *
     * @param  string  $sessionId
     * @return \Carbon\CarbonImmutable
     */
    abstract protected function sessionAuthenticatedAt(string $sessionId): CarbonImmutable;

    /**
     * The first identity's live and revoked sessions and the second's live one,
     * and the links of the live sessions.
     *
     * @return array{0: array<string, string>, 1: array<string, string>}
     */
    private function reauthenticationFixture(): array
    {
        [$identity, $other] = $this->reauthenticationIdentities();

        $at = CarbonImmutable::now()->subMinutes(10)->startOfSecond();

        [$live, $liveLink]     = $this->signInForReauthentication($identity, $at);
        [$revoked, $otherLink] = $this->signInForReauthentication($identity, $at);
        [$others, $othersLink] = $this->signInForReauthentication($other, $at);

        $this->revokeReauthenticationSession($revoked);

        return [['live' => $live, 'revoked' => $revoked, 'others' => $others], ['live' => $liveLink, 'revoked' => $otherLink, 'others' => $othersLink]];
    }

    /**
     * Lock the session, renew it to the time given and complete the renewal, in
     * one transaction on the storage connection.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  string  $linkId
     * @param  \Carbon\CarbonImmutable  $at
     * @return void
     *
     * @throws \Throwable
     */
    private function renewInTransaction(IdentityReference $identity, string $sessionId, string $linkId, CarbonImmutable $at): void
    {
        DB::connection(StorageConnection::name())->transaction(function () use ($identity, $sessionId, $linkId, $at): void {

            $sessions = $this->reauthenticationSessions();

            $sessions->lockedStanding($identity, $sessionId, $this->reauthenticationApplication(), $this->reauthenticationConnection(), $linkId);
            $sessions->renewAuthentication($identity, $sessionId, $at, null);

            $this->completeRenewal($sessionId);
        });
    }
}
