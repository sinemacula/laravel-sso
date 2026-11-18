<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing\Seams\Concerns;

use Illuminate\Database\Query\Builder;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use SineMacula\Laravel\Sso\Testing\Seams\Concerns\SessionRevocationContract;
use Tests\Fixtures\Seams\KitSessions;
use Tests\TestCase;

/**
 * Feature tests for the session revocation kit, run against a binding that
 * keeps it and ones that do not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(SessionRevocationContract::class)]
final class SessionRevocationContractTest extends TestCase
{
    use SessionRevocationContract;

    /** @var string The identity the binding's exemptions leave alone. */
    public const string EXEMPT = 'exempt';

    /** @var ?string How the binding breaks the contract, if it does. */
    private ?string $flaw = null;

    /** @var list<mixed> The integer ids of the sessions ended outside the database, as in a cache. */
    private array $endedElsewhere = [];

    /**
     * Create the sessions table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        KitSessions::create();
    }

    /**
     * Drop the sessions table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        KitSessions::drop();

        parent::tearDown();
    }

    /**
     * The kit fails a binding that ends every session of the tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCatchesABindingThatEndsTheWholeTenant(): void
    {
        $this->flaw = 'tenant';

        $this->expectException(AssertionFailedError::class);

        $this->testSessionRevocationEndsOnlyTheSessionsATenantsRuleNoLongerAllows();
    }

    /**
     * The kit fails a binding that ends an exempt identity's sessions.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCatchesABindingThatIgnoresExemptions(): void
    {
        $this->flaw = 'exemption';

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('After revocation 1, the exempt session must stand.');

        $this->testSessionRevocationEndsOnlyTheSessionsATenantsRuleNoLongerAllows();
    }

    /**
     * The kit fails a binding that leaves the sessions of a tenant inheriting
     * the rule.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCatchesABindingThatIgnoresInheritingTenants(): void
    {
        $this->flaw = 'inheritance';

        $this->expectException(AssertionFailedError::class);

        $this->testSessionRevocationEndsOnlyTheSessionsATenantsRuleNoLongerAllows();
    }

    /**
     * The kit fails a binding that narrows a connection's revocation to the
     * connection's tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCatchesABindingThatNarrowsAConnectionToItsTenant(): void
    {
        $this->flaw = 'connection-tenant';

        $this->expectException(AssertionFailedError::class);

        $this->testSessionRevocationEndsOnlyAConnectionsSessions();
    }

    /**
     * The kit fails a binding that ends the connection's sessions for a link.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCatchesABindingThatEndsEveryIdentitysSessionsForALink(): void
    {
        $this->flaw = 'link';

        $this->expectException(AssertionFailedError::class);

        $this->testSessionRevocationEndsOnlyAnIdentitysSessionsThroughALink();
    }

    /**
     * The kit fails a binding whose revocation outlives the transaction that
     * rolled it back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCatchesABindingThatRevokesOutsideTheTransaction(): void
    {
        $this->flaw = 'outside';

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A revocation rolled back must end nothing.');

        $this->testSessionRevocationRollsBackWithItsTransaction();
    }

    /**
     * The kit fails a binding that throws instead of revoking.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCatchesABindingThatThrows(): void
    {
        $this->flaw = 'throws';

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The revocation must not throw.');

        $this->testSessionRevocationRollsBackWithItsTransaction();
    }

    /**
     * A binding over the sessions table, broken as the test says.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SessionRevocation
     */
    #[\Override]
    protected function sessionRevocation(): SessionRevocation
    {
        return new readonly class ($this->flaw, $this->endSessions(...)) implements SessionRevocation {
            /**
             * Constructor.
             *
             * @param  ?string  $flaw
             * @param  \Closure(\Illuminate\Database\Query\Builder): void  $end
             */
            public function __construct(

                /** How the binding breaks the contract, if it does. */
                private ?string $flaw,

                /** End the sessions the query finds. */
                private \Closure $end,
            ) {}

            /**
             * End the scope's sessions.
             *
             * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
             * @return void
             */
            #[\Override]
            public function revoke(RevocationScope $scope): void
            {
                $sessions = match ($scope->kind) {
                    RevocationScopeKind::TENANT     => $this->ofTenant($scope),
                    RevocationScopeKind::CONNECTION => $this->ofConnection($scope),
                    default                         => $this->flaw === 'link' ? $this->ofConnection($scope) : KitSessions::query()->where('link_id', $scope->linkId),
                };

                ($this->end)($sessions);
            }

            /**
             * The sessions of the rule's tenant and those inheriting it that it
             * no longer allows.
             *
             * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
             * @return \Illuminate\Database\Query\Builder
             */
            private function ofTenant(RevocationScope $scope): Builder
            {
                if ($this->flaw === 'tenant') {
                    return KitSessions::query()->where('tenant_id', $scope->tenantId);
                }

                return KitSessions::query()
                    ->whereIn('tenant_id', $this->flaw === 'inheritance' ? [$scope->tenantId] : [$scope->tenantId, $scope->tenantId . '-child'])
                    ->when($this->flaw !== 'exemption', static fn (Builder $query): Builder => $query->where('identity_id', '!=', SessionRevocationContractTest::EXEMPT))
                    ->where(static fn (Builder $query): Builder => $query->whereNull('connection_id')->orWhereNotIn('connection_id', $scope->policy->connectionIds ?? []));
            }

            /**
             * The sessions established through the connection.
             *
             * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
             * @return \Illuminate\Database\Query\Builder
             */
            private function ofConnection(RevocationScope $scope): Builder
            {
                $sessions = KitSessions::query()->where('connection_id', $scope->connectionId);

                return $this->flaw === 'connection-tenant' ? $sessions->where('tenant_id', $scope->tenantId) : $sessions;
            }
        };
    }

    /**
     * @return array{0: string, 1: string, 2: string}
     */
    #[\Override]
    protected function revocationTenants(): array
    {
        return ['tenant-1', 'tenant-2', 'tenant-1-child'];
    }

    /**
     * @return array{0: string, 1: string}
     */
    #[\Override]
    protected function revocationConnections(): array
    {
        return ['01jballowedallowedallowed0', '01jbrefusedrefusedrefused0'];
    }

    /**
     * @return array{0: \SineMacula\Laravel\Sso\Identities\IdentityReference, 1: \SineMacula\Laravel\Sso\Identities\IdentityReference}
     */
    #[\Override]
    protected function revocationIdentities(): array
    {
        return [new IdentityReference('App\Models\User', '1'), new IdentityReference('App\Models\User', self::EXEMPT)];
    }

    /**
     * @param  string  $tenantId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $connectionId
     * @return array{0: string, 1: ?string}
     */
    #[\Override]
    protected function startRevocableSession(string $tenantId, IdentityReference $identity, ?string $connectionId): array
    {
        $link = $connectionId === null ? null : "link-of-{$identity->id}-{$connectionId}";

        return [KitSessions::start($tenantId, $identity, $connectionId, $link), $link];
    }

    /**
     * @param  string  $sessionId
     * @return bool
     */
    #[\Override]
    protected function isSessionActive(string $sessionId): bool
    {
        return !in_array((int) $sessionId, $this->endedElsewhere, true) && KitSessions::query()->where('id', $sessionId)->where('revoked', false)->exists();
    }

    /**
     * End the sessions as the binding does, broken as the test says.
     *
     * @param  \Illuminate\Database\Query\Builder  $sessions
     * @return void
     *
     * @throws \RuntimeException
     */
    private function endSessions(Builder $sessions): void
    {
        if ($this->flaw === 'throws') {
            throw new \RuntimeException('The sessions could not be revoked.');
        }

        if ($this->flaw === 'outside') {
            array_push($this->endedElsewhere, ...$sessions->pluck('id')->all());

            return;
        }

        $sessions->update(['revoked' => true]);
    }
}
