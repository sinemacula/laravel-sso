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
     * A binding over the sessions table, broken as the test says.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SessionRevocation
     */
    #[\Override]
    protected function sessionRevocation(): SessionRevocation
    {
        return new readonly class ($this->flaw) implements SessionRevocation {
            /**
             * Constructor.
             *
             * @param  ?string  $flaw
             */
            public function __construct(

                /** How the binding breaks the contract, if it does. */
                private ?string $flaw,
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

                $sessions->update(['revoked' => true]);
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
                    ->where('identity_id', '!=', SessionRevocationContractTest::EXEMPT)
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
        return KitSessions::query()->where('id', $sessionId)->where('revoked', false)->exists();
    }
}
