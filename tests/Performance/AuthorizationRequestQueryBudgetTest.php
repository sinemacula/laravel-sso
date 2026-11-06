<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\ConsumptionResult;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestConsumption;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Protocols\StartingDriver;

/**
 * Query budgets for starting a flow and consuming its request (SSO-5.1,
 * SSO-11.3, SSO-11.5, SSO-11.8):
 *
 * - a start is its attempt counted against the IP address (an update and an
 *   insert for a new counter, one update after), one read of the connection,
 *   then, in the transaction that stores the request, one locking read of the
 *   connection again, the insert of the request and the update that raises the
 *   connection's flows version; a `link` asks the freshness contract and costs
 *   the same;
 * - a start a full limit refuses stops at the limiter (its update, the insert
 *   its key refuses, the update again and one read); one whose application is
 *   not allowed at its attempt; one whose connection is unknown, or whose
 *   driver cannot start, after the connection's read;
 * - a consumption is one locking read of the request, the single-use record and
 *   the update that marks it; a replay of a marked request is the read alone; a
 *   request the store has seen the read, the refused insert, the store's delete
 *   of an expired row and the insert it refuses again; an unknown state the
 *   read alone; a correlation that names nothing no statement at all.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequestService::class)]
#[CoversClass(RequestConsumption::class)]
final class AuthorizationRequestQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var string The protocol state a consumed request was started with. */
    private const string STATE = 'the-protocol-state-of-the-request-0123456789';

    /** @var \Tests\Fixtures\Protocols\StartingDriver The driver the connection runs over. */
    private StartingDriver $driver;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection. */
    private Connection $connection;

    /**
     * Bind a freshness contract that answers `fresh` and a request from an IP
     * address, register the application and the driver, and make a usable
     * connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->driver = new StartingDriver;

        $this->app?->instance(Freshness::class, new RecordingFreshness);
        $this->app?->instance('request', Request::create('/auth/sso/authorization-requests', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', [
            'web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
        ]);

        $driver = $this->driver;

        app(ProtocolManager::class)->extend(StartingDriver::NAME, fn (): StartingDriver => $driver);

        $this->connection = $this->makeConnection([
            'protocol' => StartingDriver::NAME,
            'enabled'  => true,
            'settings' => ['issuer' => 'https://idp.example.com'],
        ]);
    }

    /**
     * The first start creates the IP address's counter; a later one updates it.
     * Each reads the connection, locks it again, inserts the request and raises
     * the connection's flows version.
     *
     * @return void
     */
    public function testAStartIsItsAttemptTwoReadsAnInsertAndAnUpdate(): void
    {
        $first = $this->assertQueryBudget(2, 4, fn (): StartResult => $this->startFlow());
        $later = $this->assertQueryBudget(2, 3, fn (): StartResult => $this->startFlow());
        $link  = $this->assertQueryBudget(2, 3, fn (): StartResult => $this->startFlow('web', Purpose::LINK, new IdentityReference('App\Models\User', '42')));

        self::assertTrue($first->isStarted());
        self::assertTrue($later->isStarted());
        self::assertTrue($link->isStarted());
        self::assertSame(3, AuthorizationRequest::query()->count());
    }

    /**
     * A refused start writes no request: a full limit stops at the limiter, an
     * application that is not allowed at its attempt, an unknown connection and
     * a driver that cannot start after reading the connection.
     *
     * @return void
     */
    public function testARefusedStartWritesNoRequest(): void
    {
        $this->startFlow('missing');

        $notAllowed = $this->assertQueryBudget(0, 1, fn (): StartResult => $this->startFlow('missing'));
        $unknown    = $this->assertQueryBudget(1, 1, fn (): StartResult => $this->startFlow(connectionId: '01jbz0000000000000000000zz'));

        $this->driver->refusal = FailureReason::METADATA_EXPIRED;

        $refused = $this->assertQueryBudget(1, 1, fn (): StartResult => $this->startFlow());

        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 4, 'decay_seconds' => 60]);

        $limited = $this->assertQueryBudget(1, 3, fn (): StartResult => $this->startFlow());

        self::assertSame(FailureReason::APPLICATION_NOT_ALLOWED, $notAllowed->reason);
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $unknown->reason);
        self::assertSame(FailureReason::METADATA_EXPIRED, $refused->reason);
        self::assertTrue($limited->isRateLimited());
        self::assertSame(0, AuthorizationRequest::query()->count());
    }

    /**
     * A consumption is one locking read, the single-use record and the update
     * that marks the request; a replay of it is the read alone.
     *
     * @return void
     */
    public function testAConsumptionIsOneReadAndTwoWrites(): void
    {
        $this->storedRequest();

        $consumed = $this->assertQueryBudget(1, 2, fn (): ConsumptionResult => $this->consume(Correlation::solicited(self::STATE)));
        $replayed = $this->assertQueryBudget(1, 0, fn (): ConsumptionResult => $this->consume(Correlation::solicited(self::STATE)));

        self::assertTrue($consumed->isConsumed());
        self::assertTrue($replayed->isReplayed());
    }

    /**
     * A request the store has seen is the read, the refused insert, the store's
     * delete of an expired row and the insert it refuses again; an unknown
     * state is the read alone; a correlation that names nothing sends nothing.
     *
     * @return void
     */
    public function testARefusedConsumptionMarksNothing(): void
    {
        $request = $this->storedRequest();

        app(SingleUseStore::class)->record(RequestConsumption::NAMESPACE, $request->id, $this->clock->now()->addMinute());

        $seen         = $this->assertQueryBudget(1, 3, fn (): ConsumptionResult => $this->consume(Correlation::solicited(self::STATE)));
        $unknown      = $this->assertQueryBudget(1, 0, fn (): ConsumptionResult => $this->consume(Correlation::solicited('another-state')));
        $uncorrelated = $this->assertQueryBudget(0, 0, fn (): ConsumptionResult => $this->consume(Correlation::uncorrelated()));

        self::assertTrue($seen->isReplayed());
        self::assertTrue($unknown->isUnknown());
        self::assertTrue($uncorrelated->isUnknown());
    }

    /**
     * Start a flow, a `sign_in` for the application through the usable
     * connection unless told otherwise.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $connectionId
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    private function startFlow(string $application = 'web', Purpose $purpose = Purpose::SIGN_IN, ?IdentityReference $identity = null, ?string $connectionId = null): StartResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(AuthorizationRequestService::class)->start($application, $purpose, $connectionId ?? $this->connection->id, Clients::browser(), null, $identity);
    }

    /**
     * Consume the request the correlation names, for a response at the usable
     * connection.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @return \SineMacula\Laravel\Sso\Flows\ConsumptionResult
     */
    private function consume(Correlation $correlation): ConsumptionResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(RequestConsumption::class)->consume($this->connection, $correlation);
    }

    /**
     * Store a request through the usable connection, started with the state.
     *
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function storedRequest(): AuthorizationRequest
    {
        return $this->makeAuthorizationRequest($this->connection, [
            'state_digest'  => hash('sha256', self::STATE),
            'code_verifier' => app(SecretEncrypter::class)->encrypt('the-pkce-verifier-of-the-request-0123456789'),
        ]);
    }
}
