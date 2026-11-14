<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Seams\Concerns;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * What every `Contracts\SessionRevocation` must guarantee, as tests: use it in
 * a test case of the binding and implement the methods it declares.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait SessionRevocationContract
{
    /**
     * A tenant's rule ends the sessions active in the tenant, or in one that
     * inherits its rule, that it no longer allows, and keeps compliant and
     * exempt ones and every other tenant's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSessionRevocationEndsOnlyTheSessionsATenantsRuleNoLongerAllows(): void
    {
        [$tenant, $outside, $inheriting] = $this->revocationTenants();
        [$allowed, $refused]             = $this->revocationConnections();
        [$person, $exempt]               = $this->revocationIdentities();

        $this->assertTheScopeEndsExactly(RevocationScope::tenant(EnforcementPolicy::required($tenant, $tenant, [$allowed], '01kitrulekitrulekitrule000')), [
            'compliant'                => [$this->startRevocableSession($tenant, $person, $allowed)[0], false],
            'other connection'         => [$this->startRevocableSession($tenant, $person, $refused)[0], true],
            'password'                 => [$this->startRevocableSession($tenant, $person, null)[0], true],
            'exempt'                   => [$this->startRevocableSession($tenant, $exempt, $refused)[0], false],
            'other tenant\'s password' => [$this->startRevocableSession($outside, $person, null)[0], false],
            'inheriting tenant\'s'     => [$this->startRevocableSession($inheriting, $person, $refused)[0], true],
        ]);
    }

    /**
     * A connection's revocation ends the sessions established through it,
     * whichever tenant they are active in now, and no other.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSessionRevocationEndsOnlyAConnectionsSessions(): void
    {
        [$tenant, $outside]  = $this->revocationTenants();
        [$allowed, $refused] = $this->revocationConnections();
        [$person]            = $this->revocationIdentities();

        $this->assertTheScopeEndsExactly(RevocationScope::connection($tenant, $refused, RevocationReason::CONNECTION_DISABLED), [
            'through the connection'     => [$this->startRevocableSession($tenant, $person, $refused)[0], true],
            'switched to another tenant' => [$this->startRevocableSession($outside, $person, $refused)[0], true],
            'through another'            => [$this->startRevocableSession($tenant, $person, $allowed)[0], false],
            'password'                   => [$this->startRevocableSession($tenant, $person, null)[0], false],
        ]);
    }

    /**
     * A removed link ends the identity's sessions through it, and neither
     * another identity's nor the identity's through another connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSessionRevocationEndsOnlyAnIdentitysSessionsThroughALink(): void
    {
        [$tenant]            = $this->revocationTenants();
        [$allowed, $refused] = $this->revocationConnections();
        [$person, $other]    = $this->revocationIdentities();
        [$linked, $link]     = $this->startRevocableSession($tenant, $person, $allowed);

        $this->assertTheScopeEndsExactly(RevocationScope::identityInConnection($tenant, $allowed, $person, (string) $link), [
            'through the link'           => [$linked, true],
            'of another identity'        => [$this->startRevocableSession($tenant, $other, $allowed)[0], false],
            'through another connection' => [$this->startRevocableSession($tenant, $person, $refused)[0], false],
        ]);
    }

    /**
     * A revocation inside a transaction that rolls back leaves its session
     * standing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSessionRevocationRollsBackWithItsTransaction(): void
    {
        [$tenant]    = $this->revocationTenants();
        [, $refused] = $this->revocationConnections();
        [$person]    = $this->revocationIdentities();
        [$session]   = $this->startRevocableSession($tenant, $person, $refused);
        $revocation  = $this->sessionRevocation();
        $rollback    = new \RuntimeException('Roll the revocation back.');

        try {
            DB::connection(StorageConnection::name())->transaction(static function () use ($revocation, $tenant, $refused, $rollback): void {
                $revocation->revoke(RevocationScope::connection($tenant, $refused, RevocationReason::CONNECTION_DISABLED));

                throw $rollback;
            });
        } catch (\RuntimeException $exception) {
            Assert::assertSame($rollback, $exception, 'The revocation must not throw.');
        }

        Assert::assertTrue($this->isSessionActive($session), 'A revocation rolled back must end nothing.');
    }

    /**
     * The binding under test.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SessionRevocation
     */
    abstract protected function sessionRevocation(): SessionRevocation;

    /**
     * Three tenants: the one revoked in, another with no rule over or from it,
     * and one that inherits its rule.
     *
     * @return array{0: string, 1: string, 2: string}
     */
    abstract protected function revocationTenants(): array;

    /**
     * Two connections of the first tenant: the one its rule allows, and
     * another.
     *
     * @return array{0: string, 1: string}
     */
    abstract protected function revocationConnections(): array;

    /**
     * Two identities: the first not exempt, the second exempt from the first
     * tenant's rule by the binding's exemptions.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Identities\IdentityReference, 1: \SineMacula\Laravel\Sso\Identities\IdentityReference}
     */
    abstract protected function revocationIdentities(): array;

    /**
     * Start a session of the identity active in the tenant, established
     * through the connection under a link of the identity's, or without SSO
     * for `null`; its id and its link's.
     *
     * @param  string  $tenantId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $connectionId
     * @return array{0: string, 1: ?string}
     */
    abstract protected function startRevocableSession(string $tenantId, IdentityReference $identity, ?string $connectionId): array;

    /**
     * Whether the session is still active.
     *
     * @param  string  $sessionId
     * @return bool
     */
    abstract protected function isSessionActive(string $sessionId): bool;

    /**
     * Revoking the scope twice, each inside a transaction on the storage
     * connection, ends exactly the sessions expected to end.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @param  array<string, array{0: string, 1: bool}>  $sessions
     * @return void
     *
     * @throws \Throwable
     */
    private function assertTheScopeEndsExactly(RevocationScope $scope, array $sessions): void
    {
        $revocation = $this->sessionRevocation();

        foreach ([1, 2] as $time) {

            DB::connection(StorageConnection::name())->transaction(static fn () => $revocation->revoke($scope));

            foreach ($sessions as $name => [$session, $ends]) {
                Assert::assertSame(!$ends, $this->isSessionActive($session), sprintf('After revocation %d, the %s session must %s.', $time, $name, $ends ? 'have ended' : 'stand'));
            }
        }
    }
}
