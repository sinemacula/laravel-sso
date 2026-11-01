<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Query budgets for completing a flow (SSO-5.6, SSO-11.3, SSO-11.5, SSO-11.8),
 * each measured once the IP address's and the connection's counters exist, so
 * every completion first costs their two updates:
 *
 * - a completion reads the connection, then, in the consumption's
 *   transaction, locks the connection and the request and writes the
 *   single-use record and the request's mark; reads the email's domain claim
 *   to build the result; then, in the locked transaction, locks the
 *   connection and the request again and marks the request completed; the
 *   linker, enforcement while it is off, the policy, the deadline contract and
 *   the issuer bound here cost nothing;
 * - a refused response and a refused consumption cost the same but the domain's
 *   read, and a connection disabled since the start the same as a
 *   refused response;
 * - a replay and a state no request has stop at the consumption's two locking
 *   reads, a response that names no request at the connection's read, and a
 *   method the endpoint does not take, an empty id and an id longer than a ULID
 *   read nothing; an unknown connection of a ULID's length is one read.
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
     * Bind the recording issuer, a linker and a request from an IP address,
     * register the application and the driver, make a usable connection that
     * maps the email, and create the counters.
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
             * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
             */
            #[\Override]
            public function resolve(VerifiedResult $result): IdentityReference
            {
                unset($result);

                return new IdentityReference('App\Models\User', '42');
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
     * A completion is six reads and five writes.
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
     * A refused response, a refused consumption and a connection disabled since
     * the start are each five reads and five writes.
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
     * A replay and a state no request has stop at the consumption's two locking
     * reads; a response that names no request at the connection's read.
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
     * A method the endpoint does not take, an empty id and an id longer than a
     * ULID read nothing; an unknown connection of a ULID's length is one read.
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
     * Complete at the callback, with the state in the query unless none is
     * given.
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

        return $app->make(CompletionService::class)->callback($connectionId ?? $this->connection->id, $request);
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
