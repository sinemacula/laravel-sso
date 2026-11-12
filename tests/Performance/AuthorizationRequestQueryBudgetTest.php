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
use SineMacula\Laravel\Sso\Identities\Caller;
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
 * Query budgets for starting a flow and consuming its request.
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
     * Answer `fresh` to every freshness check and make a usable connection.
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
     * The first start creates the IP counter, a later one updates it; then the
     * connection, its lock, the request and the flows version.
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
     * A disallowed application stops at its attempt, an unknown connection or a
     * driver that cannot start after the read, and a full limit at the limiter.
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
     * One locking read, the single-use record and the request's mark; a replay
     * is the read alone.
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
     * A seen request is the read, refused insert, expired-row delete and
     * refused insert; an unknown state reads once, an uncorrelated none.
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
     * Start a flow, by default a `sign_in` for `web` through the usable
     * connection.
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

        return $app->make(AuthorizationRequestService::class)->start(
            $application,
            $purpose,
            $connectionId ?? $this->connection->id,
            Clients::browser(),
            null,
            $identity === null ? null : new Caller($identity),
        );
    }

    /**
     * Consume the correlated request for a response at the usable connection.
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
