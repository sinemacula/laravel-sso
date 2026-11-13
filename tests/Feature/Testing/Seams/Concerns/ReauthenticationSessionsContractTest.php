<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing\Seams\Concerns;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Testing\Seams\Concerns\ReauthenticationSessionsContract;
use Tests\Fixtures\Seams\KitSessions;
use Tests\TestCase;

/**
 * Feature tests for the reauthentication sessions kit, run against a binding
 * that keeps it and ones that do not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ReauthenticationSessionsContract::class)]
final class ReauthenticationSessionsContractTest extends TestCase
{
    use ReauthenticationSessionsContract;

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
     * The kit fails a binding that stands a session for any identity.
     *
     * @return void
     */
    public function testCatchesABindingThatIgnoresTheSessionsIdentity(): void
    {
        $this->flaw = 'identity';

        $this->expectException(AssertionFailedError::class);

        $this->testReauthenticationSessionsStandOnlyForTheIdentitysLiveSession();
    }

    /**
     * The kit fails a binding that stands a session under any link of its
     * identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCatchesABindingThatChecksOnlyTheLinksOwner(): void
    {
        $this->flaw = 'link';

        $this->expectException(AssertionFailedError::class);

        $this->testReauthenticationSessionsLockASessionUnderItsExactLink();
    }

    /**
     * The kit fails a binding that renews every session of the identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCatchesABindingThatRenewsEverySessionOfTheIdentity(): void
    {
        $this->flaw = 'all';

        $this->expectException(AssertionFailedError::class);

        $this->testReauthenticationSessionsRenewOnlyTheSessionNamedForward();
    }

    /**
     * The kit fails a binding that moves a session back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCatchesABindingThatRenewsBackwards(): void
    {
        $this->flaw = 'backwards';

        $this->expectException(AssertionFailedError::class);

        $this->testReauthenticationSessionsRenewOnlyTheSessionNamedForward();
    }

    /**
     * A binding over the sessions table, broken as the test says.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions
     */
    #[\Override]
    protected function reauthenticationSessions(): ReauthenticationSessions
    {
        return new readonly class ($this->flaw) implements ReauthenticationSessions {
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
             * Signed in when the live session is the identity's, for the
             * application, through the connection.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  string  $application
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            #[\Override]
            public function standing(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection): SessionStanding
            {
                return $this->find($identity, $sessionId, $application, $connection, null, false);
            }

            /**
             * As `standing()`, under the exact link, the row locked.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  string  $application
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  string  $linkId
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            #[\Override]
            public function lockedStanding(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection, string $linkId): SessionStanding
            {
                // The flaw checks only that the link is the identity's
                $owned = str_starts_with($linkId, 'link-of-' . $identity->id . '-');

                if ($this->flaw === 'link') {
                    return $owned ? $this->find($identity, $sessionId, $application, $connection, null, true) : SessionStanding::NOT_SIGNED_IN;
                }

                return $this->find($identity, $sessionId, $application, $connection, $linkId, true);
            }

            /**
             * Renew to the later of the two times.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  \Carbon\CarbonImmutable  $authenticatedAt
             * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
             * @return void
             */
            #[\Override]
            public function renewAuthentication(IdentityReference $identity, string $sessionId, CarbonImmutable $authenticatedAt, ?AcceptedEvidence $evidence): void
            {
                unset($evidence);

                $current = KitSessions::authenticatedAt($sessionId);
                $renewed = $this->flaw === 'backwards' ? $authenticatedAt : $current->max($authenticatedAt);

                $sessions = $this->flaw === 'all' ? KitSessions::query()->where('identity_id', $identity->id) : KitSessions::query()->where('id', $sessionId);

                $sessions->update(['authenticated_at' => $renewed->utc()->format('Y-m-d H:i:s')]);
            }

            /**
             * The session's standing, by the facts given.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  string  $application
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  ?string  $linkId
             * @param  bool  $lock
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            private function find(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection, ?string $linkId, bool $lock): SessionStanding
            {
                $query = KitSessions::query()
                    ->where('id', $sessionId)
                    ->where('application', $application)
                    ->where('connection_id', $connection->getConnectionId())
                    ->where('revoked', false);

                if ($this->flaw !== 'identity') {
                    $query->where('identity_type', $identity->type)->where('identity_id', $identity->id);
                }

                if ($linkId !== null) {
                    $query->where('link_id', $linkId);
                }

                return ($lock ? $query->lockForUpdate() : $query)->exists() ? SessionStanding::SIGNED_IN : SessionStanding::NOT_SIGNED_IN;
            }
        };
    }

    /**
     * @return \SineMacula\Laravel\Sso\Contracts\SsoConnection
     */
    #[\Override]
    protected function reauthenticationConnection(): SsoConnection
    {
        return (new Connection)->forceFill(['id' => '01jbkitconnectionkitconne0', 'tenant_id' => 'tenant-1', 'protocol' => 'oidc']);
    }

    /**
     * @return string
     */
    #[\Override]
    protected function reauthenticationApplication(): string
    {
        return 'web';
    }

    /**
     * @return array{0: \SineMacula\Laravel\Sso\Identities\IdentityReference, 1: \SineMacula\Laravel\Sso\Identities\IdentityReference}
     */
    #[\Override]
    protected function reauthenticationIdentities(): array
    {
        return [new IdentityReference('App\Models\User', '1'), new IdentityReference('App\Models\User', '2')];
    }

    /**
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @return array{0: string, 1: string}
     */
    #[\Override]
    protected function signInForReauthentication(IdentityReference $identity, CarbonImmutable $authenticatedAt): array
    {
        $link = 'link-of-' . $identity->id . '-' . KitSessions::query()->count();

        return [KitSessions::start('tenant-1', $identity, '01jbkitconnectionkitconne0', $link, $authenticatedAt), $link];
    }

    /**
     * @param  string  $sessionId
     * @return void
     */
    #[\Override]
    protected function revokeReauthenticationSession(string $sessionId): void
    {
        KitSessions::query()->where('id', $sessionId)->update(['revoked' => true]);
    }

    /**
     * @param  string  $sessionId
     * @return \Carbon\CarbonImmutable
     */
    #[\Override]
    protected function sessionAuthenticatedAt(string $sessionId): CarbonImmutable
    {
        return KitSessions::authenticatedAt($sessionId);
    }
}
