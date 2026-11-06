<?php

declare(strict_types = 1);

namespace Tests\Feature\Flows;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Flows\RequestEvents;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Protocols\StartingDriver;
use Tests\TestCase;

/**
 * The events a start reports (SSO-10.1, SSO-10.2, SSO-10.4, SSO-9.8): exactly
 * `AuthorizationRequestStarted` for a request stored, with its whole context;
 * exactly one `FlowFailed` for each refusal, with its reason and as much
 * context as the start had established; exactly one
 * `FlowFailed(connection_unavailable)` for a start answered with the discovery
 * fallback; nothing for a misbound start; and never the protocol state, the
 * nonce, a verifier, a challenge or a digest.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequestService::class)]
#[CoversClass(RequestEvents::class)]
final class StartEventSequenceTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /** @var string The time every event is built at. */
    private const string OCCURRED_AT = '2026-11-01T09:30:00.000000Z';

    /** @var string The IP address every start comes from. */
    private const string IP = '203.0.113.7';

    /** @var string The user agent every start comes from. */
    private const string USER_AGENT = 'ExampleBrowser/1.0';

    /** @var string A connection id no connection has. */
    private const string UNKNOWN_ID = '01jbz0000000000000000000zz';

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract a `link` asks. */
    private RecordingFreshness $freshness;

    /** @var \Tests\Fixtures\Protocols\StartingDriver The driver the connection runs over. */
    private StartingDriver $driver;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection. */
    private Connection $connection;

    /**
     * Bind a fixed clock, a freshness contract that answers `fresh` and a
     * request from the client, register the applications and the driver, create
     * the tables and a usable connection, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = new RecordingFreshness;
        $this->driver    = new StartingDriver;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, $this->freshness);

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', [
            'web'         => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
            'discovering' => [
                'redirect_uri'     => 'https://app.example.com/sso',
                'external_sign_in' => true,
                'discovery'        => ['enabled' => true, 'fallback_url' => 'https://app.example.com/sign-in'],
            ],
        ]);

        $driver = $this->driver;

        app(ProtocolManager::class)->extend(StartingDriver::NAME, fn (): StartingDriver => $driver);

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'tenant_id' => 'tenant-7',
            'protocol'  => StartingDriver::NAME,
            'enabled'   => true,
            'settings'  => ['issuer' => 'https://idp.example.com'],
        ]);

        $this->startRecordingEvents();
    }

    /**
     * A started `sign_in` reports exactly `AuthorizationRequestStarted`, with
     * the connection, its tenant and protocol, the application, the purpose and
     * the public reference, and no failure.
     *
     * @return void
     */
    public function testAStartedSignInReportsStartedWithItsContext(): void
    {
        $result = $this->startFlow();

        $this->assertEventSequence([AuthorizationRequestStarted::class]);
        $this->assertNoFailure();

        self::assertSame($this->context([
            'connection_id'        => $this->connection->id,
            'connection_tenant_id' => 'tenant-7',
            'protocol'             => StartingDriver::NAME,
            'application'          => 'web',
            'purpose'              => 'sign_in',
            'request_reference'    => $result->reference?->value,
        ]), $this->recordedEvents()[0]->context()->toArray());

        $this->assertNoSecretIn($result);
    }

    /**
     * A started `reauthenticate` reports the identity and the session too.
     *
     * @return void
     */
    public function testAStartedReauthenticationReportsItsIdentityAndSession(): void
    {
        $this->app?->instance(ReauthenticationSessions::class, self::sessions(SessionStanding::SIGNED_IN));

        $result = $this->startFlow(Purpose::REAUTHENTICATE, identity: self::identity(), sessionId: 'session-1');

        $this->assertEventSequence([AuthorizationRequestStarted::class]);

        self::assertSame($this->context([
            'connection_id'        => $this->connection->id,
            'connection_tenant_id' => 'tenant-7',
            'protocol'             => StartingDriver::NAME,
            'application'          => 'web',
            'purpose'              => 'reauthenticate',
            'request_reference'    => $result->reference?->value,
            'identity_morph_class' => 'App\Models\User',
            'identity_id'          => '42',
            'session_id'           => 'session-1',
        ]), $this->recordedEvents()[0]->context()->toArray());

        $this->assertNoSecretIn($result);
    }

    /**
     * A full limit reports one `rate_limited`, with the purpose and the
     * identity the application gave, before any application is admitted.
     *
     * @return void
     */
    public function testAFullLimitReportsOneFailure(): void
    {
        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        $this->startFlow();
        $this->startRecordingEvents();
        $this->startFlow(Purpose::LINK, identity: self::identity());

        $this->assertEventSequence([FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::RATE_LIMITED);

        self::assertSame($this->context([
            'purpose'              => 'link',
            'identity_morph_class' => 'App\Models\User',
            'identity_id'          => '42',
        ]), $failure->context()->toArray());
    }

    /**
     * An application that is not allowed reports one failure that names no
     * application.
     *
     * @return void
     */
    public function testAnApplicationThatIsNotAllowedReportsOneFailure(): void
    {
        $this->startFlow(application: 'missing');

        $this->assertEventSequence([FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::APPLICATION_NOT_ALLOWED);

        self::assertSame($this->context(['purpose' => 'sign_in']), $failure->context()->toArray());
    }

    /**
     * A malformed challenge reports one failure that names the application.
     *
     * @return void
     */
    public function testAMalformedChallengeReportsOneFailure(): void
    {
        $this->startFlow(codeChallenge: 'not-a-challenge');

        $this->assertEventSequence([FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::CHALLENGE_INVALID);

        self::assertSame($this->context(['application' => 'web', 'purpose' => 'sign_in']), $failure->context()->toArray());
        self::assertStringNotContainsString('not-a-challenge', (string) json_encode($failure->context()->toArray()));
    }

    /**
     * An unknown connection reports one failure that names no connection; a
     * disabled one reports one that names it.
     *
     * @return void
     */
    public function testAnUnusableConnectionReportsOneFailure(): void
    {
        $this->startFlow(connectionId: self::UNKNOWN_ID);

        $this->assertEventSequence([FlowFailed::class]);

        $unknown = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::CONNECTION_UNAVAILABLE);

        self::assertSame($this->context(['application' => 'web', 'purpose' => 'sign_in']), $unknown->context()->toArray());

        $disabled = $this->makeConnection(['tenant_id' => 'tenant-9', 'protocol' => StartingDriver::NAME, 'settings' => ['issuer' => 'https://idp.example.com']]);

        $this->startRecordingEvents();
        $this->startFlow(connectionId: $disabled->id);

        $this->assertEventSequence([FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::CONNECTION_UNAVAILABLE);

        self::assertSame($this->context([
            'connection_id'        => $disabled->id,
            'connection_tenant_id' => 'tenant-9',
            'protocol'             => StartingDriver::NAME,
            'application'          => 'web',
            'purpose'              => 'sign_in',
        ]), $failure->context()->toArray());
    }

    /**
     * A start answered with the discovery fallback reports exactly one
     * `connection_unavailable`, and nothing started.
     *
     * @return void
     */
    public function testTheFallbackReportsExactlyOneConnectionUnavailable(): void
    {
        config()->set('sso.features.discovery', true);

        $result = $this->startFlow(application: 'discovering', connectionId: self::UNKNOWN_ID);

        self::assertTrue($result->isStarted());

        $this->assertEventSequence([FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::CONNECTION_UNAVAILABLE);

        self::assertSame($this->context(['application' => 'discovering', 'purpose' => 'sign_in']), $failure->context()->toArray());
        self::assertSame(0, AuthorizationRequest::query()->count());
    }

    /**
     * A stale `link` reports one `freshness_required`, with the connection.
     *
     * @return void
     */
    public function testAStaleLinkReportsOneFailure(): void
    {
        $this->freshness->answer(FreshnessOutcome::STALE);

        $this->startFlow(Purpose::LINK, identity: self::identity());

        $this->assertEventSequence([FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::FRESHNESS_REQUIRED);

        self::assertSame($this->context([
            'connection_id'        => $this->connection->id,
            'connection_tenant_id' => 'tenant-7',
            'protocol'             => StartingDriver::NAME,
            'application'          => 'web',
            'purpose'              => 'link',
            'identity_morph_class' => 'App\Models\User',
            'identity_id'          => '42',
        ]), $failure->context()->toArray());
    }

    /**
     * An ineligible session reports one `session_ineligible`, with the identity
     * and the session.
     *
     * @return void
     */
    public function testAnIneligibleSessionReportsOneFailure(): void
    {
        $this->startFlow(Purpose::REAUTHENTICATE, identity: self::identity(), sessionId: 'session-1');

        $this->assertEventSequence([FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::SESSION_INELIGIBLE);

        self::assertSame('session-1', $failure->context()->sessionId);
        self::assertSame('42', $failure->context()->identityId);
        self::assertSame($this->connection->id, $failure->context()->connectionId);
        self::assertNull($failure->context()->requestReference);
    }

    /**
     * A driver that cannot start reports one failure with its reason and the
     * reference it was given.
     *
     * @return void
     */
    public function testADriverThatCannotStartReportsOneFailureWithTheReference(): void
    {
        $this->driver->refusal = FailureReason::METADATA_EXPIRED;

        $this->startFlow();

        $this->assertEventSequence([FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::METADATA_EXPIRED);

        self::assertSame($this->context([
            'connection_id'        => $this->connection->id,
            'connection_tenant_id' => 'tenant-7',
            'protocol'             => StartingDriver::NAME,
            'application'          => 'web',
            'purpose'              => 'sign_in',
            'request_reference'    => $this->driver->lastStart()->reference->value,
        ]), $failure->context()->toArray());
    }

    /**
     * A connection disabled while the driver started reports one
     * `connection_unavailable`, with the connection and the reference, and
     * nothing started.
     *
     * @return void
     */
    public function testAConnectionChangedWhileTheDriverStartedReportsOneFailure(): void
    {
        $connection = $this->connection;

        $this->driver->onStart = static function () use ($connection): void {
            $connection->forceFill(['enabled' => false])->save();
        };

        $this->startFlow();

        $this->assertEventSequence([FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::CONNECTION_UNAVAILABLE);

        self::assertSame($this->context([
            'connection_id'        => $this->connection->id,
            'connection_tenant_id' => 'tenant-7',
            'protocol'             => StartingDriver::NAME,
            'application'          => 'web',
            'purpose'              => 'sign_in',
            'request_reference'    => $this->driver->lastStart()->reference->value,
        ]), $failure->context()->toArray());
    }

    /**
     * A misbound start reports nothing: it is application code's mistake.
     *
     * @return void
     */
    public function testAMisboundStartReportsNothing(): void
    {
        try {
            $this->startFlow(Purpose::LINK);
            self::fail('A misbound start was accepted.');
        } catch (\InvalidArgumentException) {
            $this->assertNoEvents();
        }
    }

    /**
     * Assert nothing secret the start made is in any event recorded: not the
     * protocol state, the nonce, the PKCE verifier, the client's verifier, the
     * challenge or a digest.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $result
     * @return void
     */
    private function assertNoSecretIn(StartResult $result): void
    {
        $start = $this->driver->lastStart();
        $row   = AuthorizationRequest::query()->sole();
        $shown = (string) json_encode(array_map(static fn ($event): array => $event->context()->toArray(), $this->recordedEvents()));

        $secrets = [
            $start->state->reveal(),
            $start->nonce?->reveal()        ?? '',
            $start->codeVerifier?->reveal() ?? '',
            $result->verifier?->reveal()    ?? '',
            $row->handoff_challenge,
            $row->state_digest,
            (string) $row->nonce_digest,
        ];

        foreach ($secrets as $secret) {
            self::assertNotSame('', $secret);
            self::assertStringNotContainsString($secret, $shown);
        }
    }

    /**
     * The whole context an event carries: the time and the client, the fields
     * given, and `null` for every other.
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
     * Start a flow, a `sign_in` for `web` through the usable connection unless
     * told otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  ?string  $connectionId
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \InvalidArgumentException
     */
    private function startFlow(
        Purpose $purpose = Purpose::SIGN_IN,
        string $application = 'web',
        ?string $connectionId = null,
        ?string $codeChallenge = null,
        ?IdentityReference $identity = null,
        ?string $sessionId = null,
    ): StartResult {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(AuthorizationRequestService::class)->start(
            $application,
            $purpose,
            $connectionId ?? $this->connection->id,
            self::client(),
            $codeChallenge,
            $identity,
            $sessionId,
        );
    }

    /**
     * A session contract that answers the standing given.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding  $standing
     * @return \SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions
     */
    private static function sessions(SessionStanding $standing): ReauthenticationSessions
    {
        return new readonly class ($standing) implements ReauthenticationSessions {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding  $standing
             */
            public function __construct(

                /** What every question is answered. */
                private SessionStanding $standing,
            ) {}

            /**
             * The standing given.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            #[\Override]
            public function standing(IdentityReference $identity, string $sessionId, SsoConnection $connection): SessionStanding
            {
                unset($identity, $sessionId, $connection);

                return $this->standing;
            }

            /**
             * The identity's session, locked; as `standing()` answers.
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
                unset($application, $linkId);

                return $this->standing($identity, $sessionId, $connection);
            }

            /**
             * Renew nothing.
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
                unset($identity, $sessionId, $authenticatedAt, $evidence);
            }
        };
    }

    /**
     * The identity a `link` or a `reauthenticate` is started for.
     *
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    private static function identity(): IdentityReference
    {
        return new IdentityReference('App\Models\User', '42');
    }

    /**
     * The client every action of the test is taken for: the browser's IP
     * address and user agent, which its events carry.
     *
     * @return \SineMacula\Laravel\Sso\Http\ClientContext
     */
    private static function client(): ClientContext
    {
        return new ClientContext(self::IP, self::USER_AGENT);
    }
}
