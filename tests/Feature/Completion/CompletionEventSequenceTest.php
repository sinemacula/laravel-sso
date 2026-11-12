<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionEvents;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Links\DelegatingLinkStorage;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Feature tests for the events a completion reports and their context.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionEvents::class)]
#[CoversClass(CompletionService::class)]
final class CompletionEventSequenceTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The time every event is built at. */
    private const string OCCURRED_AT = '2026-11-01T09:30:00.000000Z';

    /** @var string The IP address every completion comes from. */
    private const string IP = '203.0.113.7';

    /** @var string The user agent every completion comes from. */
    private const string USER_AGENT = 'ExampleBrowser/1.0';

    /** @var string The protocol state the request was started with. */
    private const string STATE = 'the-protocol-state-of-the-reported-request-1';

    /** @var string The request's public reference. */
    private const string REFERENCE = 'Eq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /** @var string The client's S256 challenge the request keeps. */
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /** @var string The PKCE verifier the request keeps, encrypted. */
    private const string PKCE_VERIFIER = 'the-pkce-verifier-of-the-reported-request-0';

    /** @var \Tests\Fixtures\Protocols\VerifyingDriver The driver the connection runs over. */
    private VerifyingDriver $driver;

    /** @var \Tests\Fixtures\Handoffs\RecordingHandoffIssuer The handoff issuer. */
    private RecordingHandoffIssuer $issuer;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection. */
    private Connection $connection;

    /** @var ?\SineMacula\Laravel\Sso\Identities\IdentityReference The identity every result is linked to. */
    private ?IdentityReference $linked = null;

    /**
     * Bind a fixed clock, the issuer, a linker and a request; record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->driver = new VerifyingDriver;
        $this->issuer = new RecordingHandoffIssuer;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(HandoffIssuer::class, $this->issuer);
        $this->app?->instance(Linker::class, self::linker(fn (): ?IdentityReference => $this->linked));

        $this->linked = new IdentityReference('App\Models\User', '42');

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $driver = $this->driver;

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'tenant_id'         => 'tenant-7',
            'protocol'          => VerifyingDriver::NAME,
            'enabled'           => true,
            'settings'          => ['issuer' => VerifyingDriver::ISSUER],
            'attribute_mapping' => ['email' => 'mail', 'groups' => 'memberOf'],
        ]);

        $this->startRecordingEvents();
    }

    /**
     * A completed `sign_in` reports `ResultVerified` then `HandoffIssued`.
     *
     * @return void
     */
    public function testACompletedSignInReportsResultVerifiedThenHandoffIssued(): void
    {
        $this->request();

        self::assertTrue($this->completeAtCallback()->isCompleted());

        $this->assertEventSequence([ResultVerified::class, HandoffIssued::class]);
        $this->assertNoFailure();

        $expected = $this->context($this->consumedFields() + ['identity_morph_class' => 'App\Models\User', 'identity_id' => '42']);

        self::assertSame([$expected, $expected], $this->contexts());
    }

    /**
     * A refusal after verification reports `ResultVerified`, then one failure.
     *
     * @return void
     */
    public function testARefusalAfterVerificationReportsResultVerifiedThenOneFailure(): void
    {
        $this->request();

        $this->linked = null;

        self::assertTrue($this->completeAtCallback()->isFailed());

        $this->assertEventSequence([ResultVerified::class, ResultUnlinked::class, FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::UNLINKED);

        $expected = $this->context($this->consumedFields());

        self::assertSame([$expected, $expected, $expected], $this->contexts());
    }

    /**
     * An enforcement refusal names the linked identity.
     *
     * @return void
     */
    public function testAnEnforcementRefusalNamesTheLinkedIdentity(): void
    {
        $this->request();

        $this->app?->instance(Enforcement::class, new readonly class implements Enforcement {
            /**
             * A required enforcement no connection here satisfies.
             *
             * @param  string  $tenantId
             * @param  string  $application
             * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
             */
            #[\Override]
            public function policy(string $tenantId, string $application): EnforcementPolicy
            {
                unset($application);

                return EnforcementPolicy::required($tenantId, $tenantId, ['another'], 'version-1');
            }
        });

        self::assertTrue($this->completeAtCallback()->isFailed());

        $this->assertEventSequence([ResultVerified::class, FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::ENFORCEMENT_UNSATISFIED);

        self::assertSame($this->context($this->consumedFields() + ['identity_morph_class' => 'App\Models\User', 'identity_id' => '42']), $this->contexts()[1]);
    }

    /**
     * A connection disabled during validation reports one failure after it.
     *
     * @return void
     */
    public function testAConnectionDisabledWhileValidatingReportsResultVerifiedThenOneFailure(): void
    {
        $this->request();

        $connection = $this->connection;

        $this->driver->onComplete = static function () use ($connection): void {
            Connection::query()->whereKey($connection->id)->sole()->forceFill(['enabled' => false])->save();
        };

        self::assertTrue($this->completeAtCallback()->isFailed());

        $this->assertEventSequence([ResultVerified::class, FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::CONNECTION_UNAVAILABLE);
    }

    /**
     * A response the driver refuses reports one failure with the request.
     *
     * @return void
     */
    public function testARefusedResponseReportsOneFailureWithTheRequest(): void
    {
        $this->request();

        $this->driver->refusal = FailureReason::SIGNATURE_INVALID;

        self::assertTrue($this->completeAtCallback()->isFailed());

        $this->assertEventSequence([FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::SIGNATURE_INVALID);

        self::assertSame([$this->context($this->consumedFields())], $this->contexts());
    }

    /**
     * A refused consumption reports one failure with the request.
     *
     * @return void
     */
    public function testARefusedConsumptionReportsOneFailureWithTheRequest(): void
    {
        $this->request(['expires_at' => CarbonImmutable::parse('2026-11-01T09:30:00Z')]);

        self::assertTrue($this->completeAtCallback()->isFailed());

        $this->assertEventSequence([FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::REQUEST_EXPIRED);

        self::assertSame([$this->context($this->consumedFields())], $this->contexts());
    }

    /**
     * A response no request matches reports one failure with the connection.
     *
     * @return void
     */
    public function testAResponseNoRequestMatchesReportsOneFailureWithTheConnection(): void
    {
        self::assertTrue($this->completeAtCallback('unknown-state')->isRejected());

        $this->assertEventSequence([FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::REQUEST_UNKNOWN);

        self::assertSame([$this->context($this->connectionFields())], $this->contexts());
    }

    /**
     * A refusal before the connection is read reports nothing established.
     *
     * @return void
     */
    public function testARefusalBeforeTheConnectionIsReadReportsOneFailureWithNothingEstablished(): void
    {
        self::assertTrue($this->completeAtCallback(method: 'POST')->isRejected());

        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::REQUEST_UNKNOWN);

        $this->startRecordingEvents();

        self::assertTrue($this->completeAtCallback(connectionId: '01jbz0000000000000000000zz')->isRejected());

        $this->assertEventSequence([FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::CONNECTION_UNAVAILABLE);

        self::assertSame([$this->context([])], $this->contexts());
    }

    /**
     * A protocol of the other endpoint reports one assertion-flow failure.
     *
     * @return void
     */
    public function testAProtocolOfTheOtherEndpointReportsOneFailureWithTheConnection(): void
    {
        $oidc = $this->makeConnection(['protocol' => 'oidc', 'enabled' => true]);

        $result = $this->service()->complete(
            CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
            $oidc->id,
            new CompletionRequest('POST', '', ['state' => self::STATE]),
            self::client(),
        );

        self::assertTrue($result->isRejected());

        $this->assertEventSequence([FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::ASSERTION, FailureReason::CONNECTION_UNAVAILABLE);

        self::assertSame([$this->context(['connection_id' => $oidc->id, 'connection_tenant_id' => 'tenant-1', 'protocol' => 'oidc'])], $this->contexts());
    }

    /**
     * A full limit reports exactly one `FlowFailed(rate_limited)`.
     *
     * @return void
     */
    public function testAFullLimitReportsExactlyOneFailure(): void
    {
        config()->set('sso.rate_limits.completion.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        $this->completeAtCallback('unknown-state');
        $this->startRecordingEvents();

        self::assertTrue($this->completeAtCallback()->isRateLimited());

        $this->assertEventSequence([FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::RATE_LIMITED);

        self::assertSame([$this->context([])], $this->contexts());
    }

    /**
     * A completion at the assertion consumer service reports that flow.
     *
     * @return void
     */
    public function testAnAssertionReportsTheAssertionFlow(): void
    {
        $this->request();

        $this->linked = null;

        $result = $this->service()->complete(
            CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
            $this->connection->id,
            new CompletionRequest('POST', '', ['state' => self::STATE]),
            self::client(),
        );

        self::assertTrue($result->isFailed());

        $this->assertExactlyOneFailure(Flow::ASSERTION, FailureReason::UNLINKED);
    }

    /**
     * A `link` reports the identity it was started for.
     *
     * @return void
     */
    public function testALinkReportsTheIdentityItWasStartedFor(): void
    {
        $this->request(['purpose' => 'link', 'identity_type' => 'App\Models\User', 'identity_id' => '7']);

        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
        $this->app?->instance(Linker::class, new DelegatingLinkStorage(app(LinkStore::class), LinkResolution::absent()));
        $this->linked = null;

        self::assertTrue($this->completeAtCallback()->isCompleted());

        $expected = $this->context(['purpose' => 'link', 'identity_morph_class' => 'App\Models\User', 'identity_id' => '7'] + $this->consumedFields());

        self::assertSame([$expected, $expected], $this->contexts());
    }

    /**
     * A `reauthenticate` reports the identity and session it was started for.
     *
     * @return void
     */
    public function testAReauthenticationReportsItsIdentityAndSession(): void
    {
        $this->request(['purpose' => 'reauthenticate', 'identity_type' => 'App\Models\User', 'identity_id' => '7', 'session_id' => 'session-7']);

        $this->linked = new IdentityReference('App\Models\User', '7');

        self::assertTrue($this->completeAtCallback()->isCompleted());

        $expected = $this->context([
            'purpose'              => 'reauthenticate',
            'identity_morph_class' => 'App\Models\User',
            'identity_id'          => '7',
            'session_id'           => 'session-7',
        ] + $this->consumedFields());

        self::assertSame([$expected, $expected], $this->contexts());
    }

    /**
     * No event carries a secret, the subject or an attribute.
     *
     * @return void
     */
    public function testNoEventCarriesASecretOrTheResult(): void
    {
        $request = $this->request();
        $result  = $this->completeAtCallback();
        $shown   = (string) json_encode($this->contexts());

        $secrets = [
            VerifyingDriver::SUBJECT,
            'person@example.com',
            'staff',
            self::STATE,
            $request->state_digest,
            self::CHALLENGE,
            self::PKCE_VERIFIER,
            (string) $result->handoff?->code->reveal(),
        ];

        foreach ($secrets as $secret) {
            self::assertNotSame('', $secret);
            self::assertStringNotContainsString($secret, $shown);
        }

        $this->assertEventSequence([ResultVerified::class, HandoffIssued::class]);

        foreach ($this->recordedEvents() as $event) {
            self::assertSame(['context'], array_keys(get_object_vars($event)));
        }
    }

    /**
     * The fields of a completion that consumed its request.
     *
     * @return array<string, ?string>
     */
    private function consumedFields(): array
    {
        return $this->connectionFields() + ['application' => 'web', 'purpose' => 'sign_in', 'request_reference' => self::REFERENCE];
    }

    /**
     * The fields of the connection.
     *
     * @return array<string, ?string>
     */
    private function connectionFields(): array
    {
        return ['connection_id' => $this->connection->id, 'connection_tenant_id' => 'tenant-7', 'protocol' => VerifyingDriver::NAME];
    }

    /**
     * The contexts of the events recorded, in order.
     *
     * @return list<array<string, ?string>>
     */
    private function contexts(): array
    {
        return array_map(static fn (SsoEvent $event): array => $event->context()->toArray(), $this->recordedEvents());
    }

    /**
     * The whole context an event carries, `null` for every field not given.
     *
     * @param  array<string, ?string>  $fields
     * @return array<string, ?string>
     */
    private function context(array $fields): array
    {
        return array_merge([
            'occurred_at'                 => self::OCCURRED_AT,
            'ip'                          => self::IP,
            'user_agent'                  => self::USER_AGENT,
            'connection_id'               => null,
            'connection_tenant_id'        => null,
            'protocol'                    => null,
            'application'                 => null,
            'purpose'                     => null,
            'request_reference'           => null,
            'identity_morph_class'        => null,
            'identity_id'                 => null,
            'acting_identity_morph_class' => null,
            'acting_identity_id'          => null,
            'principal_morph_class'       => null,
            'principal_id'                => null,
            'tenant_id'                   => null,
            'session_id'                  => null,
            'method'                      => null,
        ], $fields);
    }

    /**
     * Complete at the callback with the state.
     *
     * @param  string  $state
     * @param  ?string  $connectionId
     * @param  string  $method
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function completeAtCallback(string $state = self::STATE, ?string $connectionId = null, string $method = 'GET'): CompletionResult
    {
        return $this->service()->complete(
            CompletionEndpoint::CALLBACK,
            $connectionId ?? $this->connection->id,
            new CompletionRequest($method, 'state=' . $state, []),
            self::client(),
        );
    }

    /**
     * The completion service, resolved for this request.
     *
     * @return \SineMacula\Laravel\Sso\Completion\CompletionService
     */
    private function service(): CompletionService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(CompletionService::class);
    }

    /**
     * Store a `sign_in` request for `web` unless the attributes say otherwise.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function request(array $attributes = []): AuthorizationRequest
    {
        return $this->makeAuthorizationRequest($this->connection, $attributes + [
            'reference'         => self::REFERENCE,
            'state_digest'      => hash('sha256', self::STATE),
            'handoff_challenge' => self::CHALLENGE,
            'code_verifier'     => app(SecretEncrypter::class)->encrypt(self::PKCE_VERIFIER),
        ]);
    }

    /**
     * A linking contract that answers through the closure.
     *
     * @param  \Closure(): ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $resolve
     * @return \SineMacula\Laravel\Sso\Contracts\Linker
     */
    private static function linker(\Closure $resolve): Linker
    {
        return new readonly class ($resolve) implements Linker {
            /**
             * Constructor.
             *
             * @param  \Closure(): ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $resolve
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
                unset($result);

                return ExampleLinks::resolution(($this->resolve)());
            }
        };
    }

    /**
     * The client the test acts for, which its events carry.
     *
     * @return \SineMacula\Laravel\Sso\Http\ClientContext
     */
    private static function client(): ClientContext
    {
        return new ClientContext(self::IP, self::USER_AGENT);
    }
}
