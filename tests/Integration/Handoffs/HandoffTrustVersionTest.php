<?php

declare(strict_types = 1);

namespace Tests\Integration\Handoffs;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\Stages\IssueHandoff;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use Tests\Fixtures\Clients;
use Tests\Integration\Examples\ExampleTestCase;
use Tests\Integration\Examples\RedeemingAHandoff\TrustChanges;

/**
 * Integration tests for handoff codes across a change to their connection's
 * trust.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IssueHandoff::class)]
#[CoversClass(DatabaseHandoffStore::class)]
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(InFlightVoider::class)]
final class HandoffTrustVersionTest extends ExampleTestCase
{
    /** @var \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The tenant's SAML identity provider. */
    private FakeSamlIdentityProvider $idp;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person linked through it. */
    private IdentityReference $person;

    /**
     * Make the provider and a connection reading its metadata from a URL, and
     * link the person.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->idp          = new FakeSamlIdentityProvider;
        $this->connectionId = $this->makeSamlConnection($this->idp, ['metadata_url' => TrustChanges::METADATA_URL]);
        $this->person       = new IdentityReference('App\Models\User', 'person-1');

        self::assertTrue($this->linkThroughFlow($this->idp, $this->connectionId, $this->person)->isRedeemed());
    }

    /**
     * Rows of `[change, the raises of the trust version it makes]`.
     *
     * @return iterable<string, array{0: string, 1: int}>
     */
    public static function provideTrustChanges(): iterable
    {
        yield TrustChanges::REPLACED => [TrustChanges::REPLACED, 1];
        yield TrustChanges::DISTRUSTED => [TrustChanges::DISTRUSTED, 1];
        yield TrustChanges::ANCHORED => [TrustChanges::ANCHORED, 1];
        yield TrustChanges::REENABLED => [TrustChanges::REENABLED, 2];
    }

    /**
     * A trust change raises the version and voids the code, which is then
     * `handoff_unknown`.
     *
     * @param  string  $change
     * @param  int  $raises
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideTrustChanges')]
    public function testATrustChangeBetweenIssuanceAndRedemptionRefusesTheCode(string $change, int $raises): void
    {
        [$start, $redirect] = $this->issued();

        $issuedUnder = $this->trustVersion();

        self::assertSame($issuedUnder, $this->stored($redirect)->trust_version);

        $signer = (new TrustChanges(self::TENANT, $this->connectionId, $this->fetcher))->make($change, $this->idp);

        self::assertSame($issuedUnder + $raises, $this->trustVersion());
        self::assertNotNull($this->stored($redirect)->voided_at);
        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $this->admitSignIn($this->connectionId, $redirect, $start, 'session-1')->reason);
        self::assertNull($this->sessions->authenticatedAt('session-1'));

        self::assertTrue($this->signInThroughFlow($signer, $this->connectionId, 'session-2')->isRedeemed());
    }

    /**
     * Disabling and re-enabling the connection each raise its trust version
     * once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADisableAndTheEnableAfterItEachRaiseTheTrustVersion(): void
    {
        $before = $this->trustVersion();

        self::assertTrue(app(ConnectionLifecycle::class)->disable(self::TENANT, $this->connectionId, Clients::browser())->isSucceeded());
        self::assertSame($before + 1, $this->trustVersion());
        self::assertTrue(app(ConnectionService::class)->enable(self::TENANT, $this->connectionId, Clients::browser())->isSucceeded());
        self::assertSame($before + 2, $this->trustVersion());
    }

    /**
     * A raised version with the code unvoided is refused by the recheck.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVersionRaisedWithoutTheVoidIsStillRefused(): void
    {
        [$start, $redirect] = $this->issued();

        Connection::query()->whereKey($this->connectionId)->increment('trust_version');

        self::assertNull($this->stored($redirect)->voided_at);
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->admitSignIn($this->connectionId, $redirect, $start, 'session-1')->reason);
        self::assertNotNull($this->stored($redirect)->redeemed_at);
        self::assertNull($this->sessions->authenticatedAt('session-1'));
    }

    /**
     * Trusting another certificate raises nothing and voids nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAddedCertificateRefusesNothing(): void
    {
        [$start, $redirect] = $this->issued();

        $issuedUnder = $this->trustVersion();

        (new TrustChanges(self::TENANT, $this->connectionId, $this->fetcher))->added($this->idp);

        self::assertSame($issuedUnder, $this->trustVersion());
        self::assertNull($this->stored($redirect)->voided_at);

        $admitted = $this->admitSignIn($this->connectionId, $redirect, $start, 'session-1');

        self::assertTrue($admitted->isRedeemed());
        self::assertNotNull($admitted->linkedIdentity);
        self::assertTrue($this->person->is($admitted->linkedIdentity));
        self::assertNotNull($this->sessions->authenticatedAt('session-1'));
    }

    /**
     * A `sign_in` started through the connection and the provider's redirect.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: \SineMacula\Laravel\Sso\Testing\HandoffRedirect}
     *
     * @throws \Random\RandomException
     */
    private function issued(): array
    {
        $start = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);

        return [$start, $this->respondAtProvider($this->idp, $this->connectionId, $start)];
    }

    /**
     * The connection's trust version, read again.
     *
     * @return int
     */
    private function trustVersion(): int
    {
        return Connection::query()->whereKey($this->connectionId)->sole()->trust_version;
    }

    /**
     * The stored row of the code the redirect carries.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\HandoffRedirect  $redirect
     * @return \SineMacula\Laravel\Sso\Models\HandoffCode
     */
    private function stored(HandoffRedirect $redirect): HandoffCode
    {
        return HandoffCode::query()->where('code_digest', hash('sha256', $redirect->code()))->sole();
    }
}
