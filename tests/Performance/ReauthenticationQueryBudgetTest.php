<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\Redemption\ReauthenticationBranch;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesEnforcement;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Links\FixedLinker;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Query budgets for redeeming a `reauthenticate` code (SSO-5.10, SSO-9.5,
 * SSO-9.9, SSO-11.3, SSO-11.5), each measured once the IP address's counter
 * exists, so every redemption first costs its update. The linker and the
 * session contract bound here cost nothing, as an application's own session
 * rows are its own to count:
 *
 * - a redemption reads the code by its digest and the connection's tenant,
 *   then, in the caller's transaction, locks the connection and the code,
 *   writes the single-use record and the code's mark, and acknowledges no
 *   sign-in: four reads and three writes;
 * - with enforcement on, the recheck's lock adds the upsert of the tenant's
 *   enforcement row and its locking read, the connections being locked in the
 *   same one statement: five reads and four writes;
 * - a refusal once the code is consumed, by the session or by the link, costs
 *   what a redemption costs and renews nothing;
 * - a replay stops at the two locking reads, and writes only the counter;
 * - with the counters on their own connection, the counter's update goes there
 *   and the rest stays on the storage connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(ReauthenticationBranch::class)]
final class ReauthenticationQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections, UsesEnforcement;

    /** @var string The client's verifier (RFC 7636, appendix B). */
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /** @var string The session the flow was started on. */
    private const string SESSION = 'session-1';

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The identity the flow was started for. */
    private IdentityReference $identity;

    /** @var \Tests\Fixtures\Linking\RecordingSessions The session contract, bound to the identity's link. */
    private RecordingSessions $sessions;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection. */
    private Connection $connection;

    /**
     * Bind a linker answering the identity, the session contract and a request
     * from an IP address, register the driver, and make a usable connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->identity = new IdentityReference('App\Models\User', '42');
        $this->sessions = new RecordingSessions(ExampleLinks::linkId($this->identity));

        $this->app?->instance(Linker::class, new FixedLinker($this->identity));
        $this->app?->instance(ReauthenticationSessions::class, $this->sessions);
        $this->app?->instance('request', Request::create('/auth/sso/handoffs', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));

        $driver = new VerifyingDriver;

        config()->set('sso.features.oidc', true);

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->connection = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);
    }

    /**
     * A redemption is four reads and three writes, renews the session once and
     * acknowledges no sign-in.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARedemptionIsFourReadsAndThreeWrites(): void
    {
        $this->createRedemptionCounter();

        $code   = $this->issue();
        $answer = $this->assertQueryBudget(4, 3, fn (): RedemptionResult => $this->redeemCode($code));

        self::assertTrue($answer->isRedeemed());
        self::assertSame(self::SESSION, $answer->sessionId);
        self::assertSame(1, $this->sessions->renewals());
        self::assertFalse(Connection::query()->whereKey($this->connection->id)->sole()->has_completed_sign_in);
    }

    /**
     * With enforcement on, a redemption satisfying a stored rule is five reads
     * and four writes, and one the locked rule refuses the same, renewing
     * nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARedemptionUnderEnforcementLocksTheRuleFirst(): void
    {
        $this->createRedemptionCounter();

        config()->set('sso.features.enforcement', true);

        $rule      = $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$this->connection->id]]);
        $satisfied = $this->issue();
        $refused   = $this->issue();

        $answer = $this->assertQueryBudget(5, 4, fn (): RedemptionResult => $this->redeemCode($satisfied));

        self::assertTrue($answer->isRedeemed());
        self::assertSame(1, $this->sessions->renewals());

        $rule->forceFill(['connection_ids' => ['01jbotherconnection0000000']])->save();

        $refusal = $this->assertQueryBudget(5, 4, fn (): RedemptionResult => $this->redeemCode($refused));

        self::assertSame(FailureReason::ENFORCEMENT_UNSATISFIED, $refusal->reason);
        self::assertSame(1, $this->sessions->renewals());
    }

    /**
     * A refusal once the code is consumed costs what a redemption costs: a
     * session bound to another link and a subject resolving to another identity
     * are each four reads and three writes, and renew nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARefusalOnceConsumedIsFourReadsAndThreeWrites(): void
    {
        $this->createRedemptionCounter();

        $session = $this->issue();
        $link    = $this->issue();

        $this->sessions->boundLink = 'another-link';

        $ineligible = $this->assertQueryBudget(4, 3, fn (): RedemptionResult => $this->redeemCode($session));

        $this->sessions->boundLink = ExampleLinks::linkId($this->identity);

        $this->app?->instance(Linker::class, new FixedLinker(new IdentityReference('App\Models\User', '7')));

        $mismatched = $this->assertQueryBudget(4, 3, fn (): RedemptionResult => $this->redeemCode($link));

        self::assertSame(FailureReason::SESSION_INELIGIBLE, $ineligible->reason);
        self::assertSame(FailureReason::IDENTITY_MISMATCH, $mismatched->reason);
        self::assertSame(0, $this->sessions->renewals());
    }

    /**
     * A code already consumed is refused as a replay at its two locking reads,
     * and writes only the counter.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAReplayIsFourReadsAndTheCounter(): void
    {
        $this->createRedemptionCounter();

        $code = $this->issue();

        $this->redeemCode($code);

        $replay = $this->assertQueryBudget(4, 1, fn (): RedemptionResult => $this->redeemCode($code));

        self::assertSame(FailureReason::REPLAYED, $replay->reason);
        self::assertSame(1, $this->sessions->renewals());
    }

    /**
     * With the counters on their own connection, its update goes there and the
     * rest of the redemption stays on the storage connection.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheCounterGoesToItsOwnConnection(): void
    {
        $this->useSeparateCounters();
        $this->createRedemptionCounter();

        $code   = $this->issue();
        $answer = $this->assertQueryBudget(4, 2, fn (): RedemptionResult => $this->redeemCode($code), 0, 1);

        self::assertTrue($answer->isRedeemed());
        self::assertStringContainsString(DB::connection(self::COUNTERS)->getQueryGrammar()->wrapTable('sso_rate_limits'), $this->counterStatementsSent()[0]);
    }

    /**
     * Create the IP address's counter, with a value that is no code.
     *
     * @return void
     */
    private function createRedemptionCounter(): void
    {
        $this->redeemCode('a-value-that-creates-the-counter');
    }

    /**
     * Issue a `reauthenticate` code for the identity on the session, linked
     * through the identity's link.
     *
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function issue(): string
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DatabaseHandoffStore::class)->issue($this->grant())->code->reveal();
    }

    /**
     * A grant of a `reauthenticate` result through the connection.
     *
     * @return \SineMacula\Laravel\Sso\Handoffs\HandoffGrant
     */
    private function grant(): HandoffGrant
    {
        $result = new VerifiedResult(
            issuer: VerifyingDriver::ISSUER,
            subject: VerifyingDriver::SUBJECT,
            nameIdFormat: null,
            connectionId: $this->connection->id,
            tenantId: 'tenant-1',
            protocol: VerifyingDriver::NAME,
            application: 'web',
            purpose: Purpose::REAUTHENTICATE,
            requestReference: RequestReference::fromString('Iq8tVv3w0kLmNoPqRsTuVwXyZ0123456'),
            attributes: [],
            emailDomainVerified: false,
            authenticationContext: new AuthenticationContext(CarbonImmutable::parse('2026-10-31T12:00:00Z'), ['pwd']),
        );

        return new HandoffGrant(
            result: $result,
            challenge: S256Challenge::fromString('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'),
            expiresAt: $this->clock->now()->addMinute(),
            linkedIdentity: $this->identity,
            identity: $this->identity,
            sessionId: self::SESSION,
            linkId: ExampleLinks::linkId($this->identity),
        );
    }

    /**
     * Redeem the code as a `reauthenticate` for `web` through the connection,
     * in the caller's transaction, with the client's verifier.
     *
     * @param  string  $code
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function redeemCode(string $code): RedemptionResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $redemption = $app->make(HandoffRedemption::class);

        return DB::connection(StorageConnection::name())->transaction(
            fn (): RedemptionResult => $redemption->admit(Purpose::REAUTHENTICATE, 'web', $this->connection->id, $code, self::VERIFIER, $this->identity),
        );
    }
}
