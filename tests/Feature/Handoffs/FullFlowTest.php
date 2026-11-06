<?php

declare(strict_types = 1);

namespace Tests\Feature\Handoffs;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Protocols\Start;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Protocols\StartingDriver;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * A flow from end to end through the package's own parts (SSO-5.1, SSO-5.2,
 * SSO-5.6, SSO-9.2, SSO-9.9, SSO-4.3, SSO-10.1): a `sign_in` started with a
 * verifier the package generates, completed through the verifying driver with
 * the state the start sent, and its code redeemed by the package's redemption
 * with that verifier; with the linker bound to a fixture, and to the default
 * that links nothing with unlinked handoffs on. A replay, and a code redeemed
 * with another flow's verifier (an injected sign-in), are refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(DatabaseHandoffStore::class)]
final class FullFlowTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Protocols\StartingDriver The driver that records each start, and its state. */
    private StartingDriver $starting;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection. */
    private Connection $connection;

    /** @var list<\SineMacula\Laravel\Sso\Results\VerifiedResult> Every result the fixture linker was asked about. */
    private array $linkerAsked = [];

    /**
     * Bind a fixed clock and a request from an IP address, register the
     * application and a driver that starts as the starting driver and completes
     * as the verifying one, and create the tables and a usable connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock    = new FixedClock('2026-11-01T09:30:00Z');
        $this->starting = new StartingDriver;

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance('request', Request::create('/auth/sso', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $driver = self::driver($this->starting, new VerifyingDriver);

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): ProtocolDriver => $driver);

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'protocol'          => VerifyingDriver::NAME,
            'enabled'           => true,
            'settings'          => ['issuer' => VerifyingDriver::ISSUER],
            'attribute_mapping' => ['email' => 'mail'],
        ]);

        $this->startRecordingEvents();
    }

    /**
     * With the linker bound to a fixture, a `sign_in` is started, completed and
     * redeemed: the result is the one the driver verified, linked to the
     * fixture's identity, the provider's deadline limits the session, the
     * connection has completed a sign-in, and the flow reported its four events
     * under the start's reference. Redeemed again, the code is a replay.
     *
     * @return void
     */
    public function testASignInFromStartToRedemptionWithALinkedIdentity(): void
    {
        $this->bindFixtureLinker();

        $start      = $this->start();
        $completion = $this->complete();
        $reference  = $start->reference;
        $verifier   = (string) $start->verifier?->reveal();

        self::assertNotNull($reference);
        self::assertTrue($completion->isCompleted());

        $code   = (string) $completion->handoff?->code->reveal();
        $answer = $this->redeem($code, $verifier);

        self::assertTrue($answer->isRedeemed());
        self::assertNotNull($answer->result);
        $this->assertVerifiedResult($answer->result, $reference->value);
        self::assertSame(['type' => 'App\Models\User', 'id' => '42'], $answer->linkedIdentity?->jsonSerialize());
        self::assertNull($answer->identity);
        self::assertNull($answer->sessionId);
        self::assertNull($answer->enforcementVersion);
        self::assertSame('2026-11-01T18:00:00+00:00', $answer->sessionNotAfter?->toIso8601String());
        self::assertTrue(Connection::query()->whereKey($this->connection->id)->sole()->has_completed_sign_in);
        self::assertCount(2, $this->linkerAsked);
        self::assertSame($this->linkerAsked[0]->toArray(), $this->linkerAsked[1]->toArray());

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, HandoffIssued::class, HandoffRedeemed::class]);

        foreach ($this->recordedEvents() as $event) {
            self::assertSame($reference->value, $event->context()->requestReference);
        }

        self::assertSame(FailureReason::REPLAYED, $this->redeem($code, $verifier)->reason);
    }

    /**
     * With the default linker, which links nothing, and unlinked handoffs on,
     * the `sign_in` is handed off unlinked and redeemed with no linked
     * identity, and no completed sign-in is recorded.
     *
     * @return void
     */
    public function testAnUnlinkedSignInFromStartToRedemption(): void
    {
        config()->set('sso.applications.web.unlinked_handoffs', true);

        self::assertInstanceOf(NoLinks::class, $this->app?->make(Linker::class));

        $start      = $this->start();
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());

        $answer = $this->redeem((string) $completion->handoff?->code->reveal(), (string) $start->verifier?->reveal());

        self::assertTrue($answer->isRedeemed());
        self::assertNull($answer->linkedIdentity);
        self::assertSame(VerifyingDriver::SUBJECT, $answer->result?->subject);
        self::assertFalse(Connection::query()->whereKey($this->connection->id)->sole()->has_completed_sign_in);

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, ResultUnlinked::class, HandoffIssued::class, HandoffRedeemed::class]);
    }

    /**
     * A code redeemed with the verifier of another flow, as an attacker's
     * completed sign-in injected into a victim's client would be, is
     * `verifier_mismatch`, and the code is spent.
     *
     * @return void
     */
    public function testACodeRedeemedWithAnotherFlowsVerifierIsRefused(): void
    {
        $this->bindFixtureLinker();

        $attacker   = $this->start();
        $completion = $this->complete();
        $victim     = $this->start();
        $code       = (string) $completion->handoff?->code->reveal();

        self::assertNotSame($attacker->verifier?->reveal(), $victim->verifier?->reveal());
        self::assertSame(FailureReason::VERIFIER_MISMATCH, $this->redeem($code, (string) $victim->verifier?->reveal())->reason);
        self::assertSame(FailureReason::REPLAYED, $this->redeem($code, (string) $attacker->verifier?->reveal())->reason);
        self::assertFalse(Connection::query()->whereKey($this->connection->id)->sole()->has_completed_sign_in);
    }

    /**
     * Assert the redeemed result is the one the verifying driver verified for
     * the flow under the reference.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  string  $reference
     * @return void
     */
    private function assertVerifiedResult(VerifiedResult $result, string $reference): void
    {
        self::assertSame(VerifyingDriver::ISSUER, $result->issuer);
        self::assertSame(VerifyingDriver::SUBJECT, $result->subject);
        self::assertSame($this->connection->id, $result->connectionId);
        self::assertSame('tenant-1', $result->tenantId);
        self::assertSame('web', $result->application);
        self::assertSame(Purpose::SIGN_IN, $result->purpose);
        self::assertSame($reference, $result->requestReference->value);
        self::assertSame(['email' => 'person@example.com'], $result->attributes);
    }

    /**
     * Bind a linker that links every result to one identity, recording each
     * result it is asked about.
     *
     * @return void
     */
    private function bindFixtureLinker(): void
    {
        $resolve = function (VerifiedResult $result): IdentityReference {
            $this->linkerAsked[] = $result;

            return new IdentityReference('App\Models\User', '42');
        };

        $this->app?->instance(Linker::class, new readonly class ($resolve) implements Linker {
            /**
             * Constructor.
             *
             * @param  \Closure(\SineMacula\Laravel\Sso\Results\VerifiedResult): \SineMacula\Laravel\Sso\Identities\IdentityReference  $resolve
             */
            public function __construct(

                /** What every result resolves to. */
                private \Closure $resolve,
            ) {}

            /**
             * What the closure answers.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
            {
                return ExampleLinks::resolution(($this->resolve)($result));
            }
        });
    }

    /**
     * Start a `sign_in` for `web` through the connection, the package
     * generating the verifier.
     *
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    private function start(): StartResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app   = $this->app;
        $start = $app->make(AuthorizationRequestService::class)->start('web', Purpose::SIGN_IN, $this->connection->id, Clients::browser());

        self::assertTrue($start->isStarted());
        self::assertNotNull($start->verifier);

        return $start;
    }

    /**
     * Complete the last flow started at the callback, with the state its start
     * sent the provider.
     *
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(): CompletionResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app   = $this->app;
        $state = $this->starting->lastStart()->state->reveal();

        return $app->make(CompletionService::class)->complete(
            CompletionEndpoint::CALLBACK,
            $this->connection->id,
            new CompletionRequest('GET', 'state=' . rawurlencode($state), []),
            Clients::browser(),
        );
    }

    /**
     * Redeem the code as a `sign_in` for `web` through the connection, with the
     * verifier.
     *
     * @param  string  $code
     * @param  string  $verifier
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function redeem(string $code, string $verifier): RedemptionResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $redemption = $app->make(HandoffRedemption::class);

        return DB::connection(StorageConnection::name())->transaction(
            fn (): RedemptionResult => $redemption->redeem(Purpose::SIGN_IN, 'web', $this->connection->id, $code, $verifier, Clients::browser()),
        );
    }

    /**
     * A driver that starts as the starting driver and validates as the
     * verifying one.
     *
     * @param  \Tests\Fixtures\Protocols\StartingDriver  $starting
     * @param  \Tests\Fixtures\Protocols\VerifyingDriver  $verifying
     * @return \SineMacula\Laravel\Sso\Contracts\ProtocolDriver
     */
    private static function driver(StartingDriver $starting, VerifyingDriver $verifying): ProtocolDriver
    {
        return new readonly class ($starting, $verifying) implements ProtocolDriver {
            /**
             * Constructor.
             *
             * @param  \Tests\Fixtures\Protocols\StartingDriver  $starting
             * @param  \Tests\Fixtures\Protocols\VerifyingDriver  $verifying
             */
            public function __construct(

                /** Starts each flow, recording its state. */
                private StartingDriver $starting,

                /** Correlates and validates each response. */
                private VerifyingDriver $verifying,
            ) {}

            /**
             * The verifying driver's settings.
             *
             * @param  array<array-key, mixed>  $values
             * @return \SineMacula\Laravel\Sso\Contracts\ProtocolSettings
             */
            #[\Override]
            public function settings(array $values): ProtocolSettings
            {
                return $this->verifying->settings($values);
            }

            /**
             * Whether the verifying driver counts the connection complete.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return bool
             */
            #[\Override]
            public function isComplete(SsoConnection $connection): bool
            {
                return $this->verifying->isComplete($connection);
            }

            /**
             * Start as the starting driver.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
             * @return \SineMacula\Laravel\Sso\Protocols\Start
             */
            #[\Override]
            public function start(SsoConnection $connection, StartRequest $request): Start
            {
                return $this->starting->start($connection, $request);
            }

            /**
             * Correlate as the verifying driver.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
             * @return \SineMacula\Laravel\Sso\Protocols\Correlation
             */
            #[\Override]
            public function correlate(SsoConnection $connection, CompletionRequest $request): Correlation
            {
                return $this->verifying->correlate($connection, $request);
            }

            /**
             * Validate as the verifying driver.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
             * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
             * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
             * @return \SineMacula\Laravel\Sso\Protocols\Completion
             */
            #[\Override]
            public function complete(SsoConnection $connection, CompletionRequest $request, ConsumedRequest $consumed, ClientContext $client): Completion
            {
                return $this->verifying->complete($connection, $request, $consumed, $client);
            }

            /**
             * Describe as the verifying driver.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
             */
            #[\Override]
            public function describe(SsoConnection $connection): ServiceProviderDescription
            {
                return $this->verifying->describe($connection);
            }
        };
    }
}
