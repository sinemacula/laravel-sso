<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Links\DelegatingLinkStorage;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Query budgets for issuing and redeeming handoff codes (SSO-9.2, SSO-11.3,
 * SSO-11.5, SSO-11.8), each redemption measured once the IP address's counter
 * exists, so every redemption first costs its update:
 *
 * - issuing a code is one insert and the update that raises its connection's
 *   flows version;
 * - a linked `sign_in` redeemed reads the code by its digest and the
 *   connection's tenant, then, in its transaction, locks the connection and the
 *   code, writes the single-use record and the code's mark, and marks the
 *   connection's first completed sign-in on the row it holds locked; once
 *   marked, the connection is not written again; the linker and enforcement
 *   while it is off cost nothing;
 * - a `link` is not acknowledged; it upserts its identity's guard first, reads
 *   by a locking read whether the identity has held a verified domain link,
 *   finds by a plain read the connections holding its verified domain links,
 *   and reads those links in its judgement and again in its admission;
 * - with enforcement on, the recheck's lock adds the upsert of the tenant's
 *   enforcement row and its locking read, and the connections are locked in the
 *   same one statement, the rule's with them;
 * - a refusal once the code is consumed stops before the recheck, and one by
 *   the recheck after it, with no lock more;
 * - a replay and a voided code stop at the two locking reads, a code whose
 *   connection is gone at the read of its tenant, a code never issued at its
 *   read, and a value that is not a code reads nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(DatabaseHandoffStore::class)]
final class HandoffQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections;

    /** @var string The client's verifier (RFC 7636, appendix B). */
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection. */
    private Connection $connection;

    /**
     * Bind a linker that links every result to one identity and a request from
     * an IP address, register the driver, make a usable connection, and create
     * the IP address's counter.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Linker::class, new readonly class implements Linker {
            /**
             * One identity for every result.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
            {
                unset($result);

                return ExampleLinks::resolution(new IdentityReference('App\Models\User', '42'));
            }
        });
        $this->app?->instance('request', Request::create('/auth/sso/handoffs', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));

        $driver = new VerifyingDriver;

        config()->set('sso.features.oidc', true);

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->connection = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);

        $this->redeem('a-value-that-creates-the-counter');
    }

    /**
     * Issuing a code is one insert, and one update that raises its connection's
     * flows version.
     *
     * @return void
     */
    public function testIssuingACodeIsOneInsertAndOneUpdate(): void
    {
        $issued = $this->assertQueryBudget(0, 2, fn (): IssuedHandoff => $this->store()->issue($this->grant()));

        self::assertSame(1, StoredCode::query()->count());
        self::assertSame(1, Connection::query()->findOrFail($this->connection->id)->flows_version);
        self::assertSame(hash('sha256', $issued->code->reveal()), StoredCode::query()->sole()->code_digest);
    }

    /**
     * The first linked `sign_in` redeemed through a connection is four reads
     * and four writes; the next is four reads and three writes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testALinkedSignInRedeemedIsFourReadsAndFourWritesThenThree(): void
    {
        $first  = $this->issue();
        $second = $this->issue();

        $redeemed = $this->assertQueryBudget(4, 4, fn (): RedemptionResult => $this->redeem($first));
        $again    = $this->assertQueryBudget(4, 3, fn (): RedemptionResult => $this->redeem($second));

        self::assertTrue($redeemed->isRedeemed());
        self::assertTrue($again->isRedeemed());
    }

    /**
     * With enforcement on, the first linked `sign_in` redeemed for a tenant
     * with no rule is five reads and five writes (the guard's upsert, which
     * inserts the unconfigured row, among them); with a rule stored, the next
     * is five reads and four writes; and a redemption the locked rule refuses
     * is five reads and four writes too.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testALinkedSignInRedeemedUnderEnforcementLocksTheRuleFirst(): void
    {
        config()->set('sso.features.enforcement', true);

        $first  = $this->issue();
        $second = $this->issue();
        $third  = $this->issue();

        $unruled = $this->assertQueryBudget(5, 5, fn (): RedemptionResult => $this->redeem($first));

        TenantEnforcement::query()->sole()->forceFill(['enabled' => true, 'connection_ids' => [$this->connection->id], 'version' => '01jbexampleversion00000001'])->save();

        $ruled = $this->assertQueryBudget(5, 4, fn (): RedemptionResult => $this->redeem($second));

        TenantEnforcement::query()->sole()->forceFill(['connection_ids' => ['01jbotherconnection0000000']])->save();

        $refused = $this->assertQueryBudget(5, 4, fn (): RedemptionResult => $this->redeem($third));

        self::assertTrue($unruled->isRedeemed());
        self::assertTrue($ruled->isRedeemed());
        self::assertSame(FailureReason::ENFORCEMENT_UNSATISFIED, $refused->reason);
    }

    /**
     * A `link` redeemed is nine reads and four writes: it acknowledges no
     * sign-in; it upserts the identity's guard (the fourth write), reads by a
     * locking read whether the identity has ever held a verified domain link,
     * and finds by a plain read the connections holding its verified domain
     * links; it reads the link it confirms, and the identity's verified domain
     * links in its judgement and again in its admission.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testALinkRedeemedIsNineReadsAndFourWrites(): void
    {
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);

        $identity = new IdentityReference('App\Models\User', '42');

        $this->app?->instance(Linker::class, new DelegatingLinkStorage(app(LinkStore::class), ExampleLinks::resolution($identity)));

        $code   = $this->issue(Purpose::LINK);
        $answer = $this->assertQueryBudget(9, 4, fn (): RedemptionResult => $this->redeem($code, Purpose::LINK));

        self::assertTrue($answer->isRedeemed());
    }

    /**
     * A refusal once the code is consumed is four reads and three writes, and a
     * refusal by the recheck the same: it locks nothing more.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARefusalOnceTheCodeIsConsumed(): void
    {
        $mismatched = $this->issue();
        $expired    = $this->issue(expiresAt: $this->clock->now());
        $disabled   = $this->issue();

        $purpose = $this->assertQueryBudget(4, 3, fn (): RedemptionResult => $this->redeem($mismatched, Purpose::LINK));
        $expiry  = $this->assertQueryBudget(4, 3, fn (): RedemptionResult => $this->redeem($expired));

        $this->connection->forceFill(['enabled' => false])->save();

        $unavailable = $this->assertQueryBudget(4, 3, fn (): RedemptionResult => $this->redeem($disabled));

        self::assertSame(FailureReason::PURPOSE_MISMATCH, $purpose->reason);
        self::assertSame(FailureReason::HANDOFF_EXPIRED, $expiry->reason);
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $unavailable->reason);
    }

    /**
     * A replay and a voided code are four reads and the counter's write; a code
     * whose connection is gone two reads.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACodeNotConsumedWritesOnlyTheCounter(): void
    {
        $replayed = $this->issue();
        $voided   = $this->issue();
        $orphaned = $this->issue();

        $this->redeem($replayed);
        StoredCode::query()->where('code_digest', hash('sha256', $voided))->sole()->forceFill(['voided_at' => $this->clock->now()])->save();
        StoredCode::query()->where('code_digest', hash('sha256', $orphaned))->sole()->forceFill(['connection_id' => '01jbz0000000000000000000zz'])->save();

        $replay = $this->assertQueryBudget(4, 1, fn (): RedemptionResult => $this->redeem($replayed));
        $void   = $this->assertQueryBudget(4, 1, fn (): RedemptionResult => $this->redeem($voided));
        $gone   = $this->assertQueryBudget(2, 1, fn (): RedemptionResult => $this->redeem($orphaned));

        self::assertSame(FailureReason::REPLAYED, $replay->reason);
        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $void->reason);
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $gone->reason);
    }

    /**
     * A code never issued is one read and the counter's write; a value that is
     * not a code reads nothing.
     *
     * @return void
     */
    public function testAnUnknownCodeReadsAtMostItsDigest(): void
    {
        $unknown   = $this->assertQueryBudget(1, 1, fn (): RedemptionResult => $this->redeem(str_repeat('A', 43)));
        $malformed = $this->assertQueryBudget(0, 1, fn (): RedemptionResult => $this->redeem('not-a-code'));

        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $unknown->reason);
        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $malformed->reason);
    }

    /**
     * Issue a code for the purpose, expiring a minute from now unless given.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function issue(Purpose $purpose = Purpose::SIGN_IN, ?CarbonImmutable $expiresAt = null): string
    {
        return $this->store()->issue($this->grant($purpose, $expiresAt))->code->reveal();
    }

    /**
     * A grant of a result through the connection, linked to one identity.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @return \SineMacula\Laravel\Sso\Handoffs\HandoffGrant
     */
    private function grant(Purpose $purpose = Purpose::SIGN_IN, ?CarbonImmutable $expiresAt = null): HandoffGrant
    {
        $result = new VerifiedResult(
            issuer: VerifyingDriver::ISSUER,
            subject: VerifyingDriver::SUBJECT,
            nameIdFormat: null,
            connectionId: $this->connection->id,
            tenantId: 'tenant-1',
            protocol: VerifyingDriver::NAME,
            application: 'web',
            purpose: $purpose,
            requestReference: RequestReference::fromString('Iq8tVv3w0kLmNoPqRsTuVwXyZ0123456'),
            attributes: [],
            emailDomainVerified: false,
            authenticationContext: new AuthenticationContext(CarbonImmutable::parse('2026-10-31T12:00:00Z'), ['pwd']),
        );

        return new HandoffGrant(
            result: $result,
            challenge: S256Challenge::fromString('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'),
            expiresAt: $expiresAt ?? $this->clock->now()->addMinute(),
            trustVersion: $this->connection->trust_version,
            linkedIdentity: new IdentityReference('App\Models\User', '42'),
            linkId: 'link-42',
            identity: $purpose === Purpose::SIGN_IN ? null : new IdentityReference('App\Models\User', '42'),
        );
    }

    /**
     * Redeem the code for `web` through the connection with the client's
     * verifier.
     *
     * @param  string  $code
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function redeem(string $code, Purpose $purpose = Purpose::SIGN_IN): RedemptionResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $redemption = $app->make(HandoffRedemption::class);
        $caller     = new IdentityReference('App\Models\User', '42');

        return DB::connection(StorageConnection::name())->transaction(
            fn (): RedemptionResult => $redemption->redeem($purpose, 'web', $this->connection->id, $code, self::VERIFIER, Clients::browser(), $caller),
        );
    }

    /**
     * The package's store.
     *
     * @return \SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore
     */
    private function store(): DatabaseHandoffStore
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DatabaseHandoffStore::class);
    }
}
