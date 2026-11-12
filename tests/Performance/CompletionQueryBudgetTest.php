<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Query budgets for completing a flow, measured once the IP and connection
 * counters exist, so each costs their two updates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(CompletionPipeline::class)]
final class CompletionQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var string The protocol state the request was started with. */
    private const string STATE = 'the-protocol-state-of-the-budgeted-request-1';

    /** @var \Tests\Fixtures\Protocols\VerifyingDriver The driver the connection runs over. */
    private VerifyingDriver $driver;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection. */
    private Connection $connection;

    /**
     * Register the driver, make a usable connection that maps the email, and
     * create the counters.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->driver = new VerifyingDriver;

        $this->app?->instance(HandoffIssuer::class, new RecordingHandoffIssuer);
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
        $this->app?->instance('request', Request::create('/auth/sso/connections/x/callback', 'GET', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $driver = $this->driver;

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->connection = $this->makeConnection([
            'protocol'          => VerifyingDriver::NAME,
            'enabled'           => true,
            'settings'          => ['issuer' => VerifyingDriver::ISSUER],
            'attribute_mapping' => ['email' => 'mail'],
        ]);

        $this->completeAtCallback('a-state-that-creates-the-counters');
    }

    /**
     * The connection; the consumption's two locks, single-use record and mark;
     * the domain claim; the two locks again and the completed mark.
     *
     * @return void
     */
    public function testACompletionIsSixReadsAndFiveWrites(): void
    {
        $this->request(self::STATE);

        $result = $this->assertQueryBudget(6, 5, fn (): CompletionResult => $this->completeAtCallback(self::STATE));

        self::assertTrue($result->isCompleted());
    }

    /**
     * Enforcement adds the rule row's upsert and lock, and locks the rule's
     * connections with the connection; a stored rule costs the same.
     *
     * @return void
     */
    public function testACompletionUnderEnforcementLocksTheRuleFirst(): void
    {
        config()->set('sso.features.enforcement', true);

        $this->request(self::STATE);

        $unruled = $this->assertQueryBudget(7, 6, fn (): CompletionResult => $this->completeAtCallback(self::STATE));

        TenantEnforcement::query()->sole()->forceFill(['enabled' => true, 'connection_ids' => [$this->connection->id], 'version' => '01jbexampleversion00000001'])->save();

        $this->request('a-second-state');

        $ruled = $this->assertQueryBudget(7, 6, fn (): CompletionResult => $this->completeAtCallback('a-second-state'));

        self::assertTrue($unruled->isCompleted());
        self::assertTrue($ruled->isCompleted());
    }

    /**
     * A refused response, a refused consumption and a connection disabled since
     * the start skip only the domain's read.
     *
     * @return void
     */
    public function testARefusalOnceTheRequestIsConsumedIsFiveReadsAndFiveWrites(): void
    {
        $this->request('refused');
        $this->request('expired', ['expires_at' => $this->clock->now()]);
        $this->request('disabled');

        $this->driver->refusal = FailureReason::SIGNATURE_INVALID;

        $refused = $this->assertQueryBudget(5, 5, fn (): CompletionResult => $this->completeAtCallback('refused'));
        $expired = $this->assertQueryBudget(5, 5, fn (): CompletionResult => $this->completeAtCallback('expired'));

        $this->connection->forceFill(['enabled' => false])->save();

        $disabled = $this->assertQueryBudget(5, 5, fn (): CompletionResult => $this->completeAtCallback('disabled'));

        self::assertSame(FailureReason::SIGNATURE_INVALID, $refused->reason);
        self::assertSame(FailureReason::REQUEST_EXPIRED, $expired->reason);
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $disabled->reason);
        self::assertSame(3, AuthorizationRequest::query()->whereNotNull('completed_at')->count());
    }

    /**
     * A replay and an unknown state stop at the consumption's two locking
     * reads; an uncorrelated response at the connection's read.
     *
     * @return void
     */
    public function testAResponseNoRequestMatchesWritesNothingButItsCounters(): void
    {
        $this->request(self::STATE);
        $this->completeAtCallback(self::STATE);

        $replayed     = $this->assertQueryBudget(3, 2, fn (): CompletionResult => $this->completeAtCallback(self::STATE));
        $unknown      = $this->assertQueryBudget(3, 2, fn (): CompletionResult => $this->completeAtCallback('another-state'));
        $uncorrelated = $this->assertQueryBudget(1, 2, fn (): CompletionResult => $this->completeAtCallback(null));

        foreach ([$replayed, $unknown, $uncorrelated] as $result) {
            self::assertSame(FailureReason::REQUEST_UNKNOWN, $result->reason);
        }
    }

    /**
     * A wrong method, an empty id and an id longer than a ULID read nothing; an
     * unknown ULID-length id is one read.
     *
     * @return void
     */
    public function testARefusalBeforeTheConnectionIsFoundReadsAtMostTheConnection(): void
    {
        $unknownId = '01jbz0000000000000000000zz';
        $longId    = $unknownId . 'z';

        foreach (['', $longId, $unknownId] as $connectionId) {
            $this->completeAtCallback(null, $connectionId);
        }

        $method  = $this->assertQueryBudget(0, 2, fn (): CompletionResult => $this->completeAtCallback(self::STATE, method: 'POST'));
        $empty   = $this->assertQueryBudget(0, 2, fn (): CompletionResult => $this->completeAtCallback(self::STATE, ''));
        $long    = $this->assertQueryBudget(0, 2, fn (): CompletionResult => $this->completeAtCallback(self::STATE, $longId));
        $unknown = $this->assertQueryBudget(1, 2, fn (): CompletionResult => $this->completeAtCallback(self::STATE, $unknownId));

        self::assertSame(FailureReason::REQUEST_UNKNOWN, $method->reason);

        foreach ([$empty, $long, $unknown] as $result) {
            self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $result->reason);
        }
    }

    /**
     * Complete at the callback, with the state in the query when given.
     *
     * @param  ?string  $state
     * @param  ?string  $connectionId
     * @param  string  $method
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function completeAtCallback(?string $state, ?string $connectionId = null, string $method = 'GET'): CompletionResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $request = new CompletionRequest($method, $state === null ? '' : 'state=' . $state, []);

        return $app->make(CompletionService::class)->complete(CompletionEndpoint::CALLBACK, $connectionId ?? $this->connection->id, $request, Clients::browser());
    }

    /**
     * Store a request through the connection, started with the state.
     *
     * @param  string  $state
     * @param  array<string, mixed>  $attributes
     * @return void
     */
    private function request(string $state, array $attributes = []): void
    {
        $this->makeAuthorizationRequest($this->connection, $attributes + [
            'state_digest'      => hash('sha256', $state),
            'handoff_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_verifier'     => app(SecretEncrypter::class)->encrypt('the-pkce-verifier-of-the-budgeted-request-1'),
        ]);
    }
}
