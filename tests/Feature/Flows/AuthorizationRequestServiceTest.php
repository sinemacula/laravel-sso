<?php

declare(strict_types = 1);

namespace Tests\Feature\Flows;

use Carbon\CarbonImmutable;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\ApplicationRegistry;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Flows\Enums\StartStatus;
use SineMacula\Laravel\Sso\Flows\ProtocolState;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Flows\Verifier;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\Fixtures\Protocols\StartingDriver;
use Tests\TestCase;

/**
 * Feature tests for starting a flow through the authorisation request service.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequestService::class)]
#[CoversClass(ProtocolState::class)]
final class AuthorizationRequestServiceTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /** @var string The IP address every start comes from. */
    private const string IP = '203.0.113.7';

    /** @var string The discovery fallback of the `discovering` application. */
    private const string FALLBACK = 'https://app.example.com/sign-in';

    /** @var string A connection id no connection has. */
    private const string UNKNOWN_ID = '01jbz0000000000000000000zz';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Http\ClientContext The client every start is made for. */
    private ClientContext $client;

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract a `link` asks. */
    private RecordingFreshness $freshness;

    /** @var \Tests\Fixtures\Protocols\StartingDriver The driver the connection runs over. */
    private StartingDriver $driver;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection. */
    private Connection $connection;

    /**
     * Bind a fixed clock, fresh freshness and a client request, register the
     * applications and driver, and seed a usable connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock     = new FixedClock('2026-11-01T09:30:00Z');
        $this->freshness = new RecordingFreshness;
        $this->driver    = new StartingDriver;

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Freshness::class, $this->freshness);
        $this->client = new ClientContext(self::IP, null);

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', [
            'web'         => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
            'closed'      => ['redirect_uri' => 'https://closed.example.com/sso'],
            'discovering' => [
                'redirect_uri'     => 'https://app.example.com/sso',
                'external_sign_in' => true,
                'discovery'        => ['enabled' => true, 'fallback_url' => self::FALLBACK],
            ],
        ]);

        $driver = $this->driver;

        app(ProtocolManager::class)->extend(StartingDriver::NAME, fn (): StartingDriver => $driver);

        $this->usePackageTables();

        $this->connection = $this->usableConnection();
    }

    /**
     * A `sign_in` without a challenge is started outside any transaction and
     * stored exactly.
     *
     * @return void
     */
    public function testASignInIsStartedAndStoredExactly(): void
    {
        $levels = [];

        $this->driver->onStart = static function () use (&$levels): void {
            $levels[] = DB::connection(StorageConnection::name())->transactionLevel();
        };

        $result = $this->startFlow();
        $start  = $this->driver->lastStart();
        $row    = self::onlyRequest();

        self::assertSame(StartStatus::STARTED, $result->status);
        self::assertSame([0], $levels);
        self::assertNotNull($result->reference);
        self::assertNotNull($result->verifier);
        self::assertSame(Purpose::SIGN_IN, $start->purpose);
        self::assertSame('web', $start->application);
        self::assertSame($result->reference->value, $start->reference->value);
        self::assertNotNull($start->nonce);
        self::assertNotNull($start->codeVerifier);

        $state    = $start->state->reveal();
        $nonce    = $start->nonce->reveal();
        $pkce     = $start->codeVerifier->reveal();
        $verifier = $result->verifier->reveal();

        self::assertCount(5, array_unique([$result->reference->value, $state, $nonce, $pkce, $verifier]));
        self::assertSame([43, 43, 43, 43], [strlen($state), strlen($nonce), strlen($pkce), strlen($verifier)]);

        self::assertSame([
            'reference'         => $result->reference->value,
            'state_digest'      => hash('sha256', $state),
            'purpose'           => Purpose::SIGN_IN,
            'application'       => 'web',
            'connection_id'     => $this->connection->id,
            'expected_issuer'   => 'https://idp.example.com',
            'issuer_required'   => false,
            'nonce_digest'      => hash('sha256', $nonce),
            'saml_request_id'   => null,
            'handoff_challenge' => $result->verifier->challenge()->value,
            'trust_version'     => 0,
            'identity_type'     => null,
            'identity_id'       => null,
            'session_id'        => null,
            'expires_at'        => '2026-11-01T09:40:00+00:00',
            'consumed_at'       => null,
            'voided_at'         => null,
            'completed_at'      => null,
            'created_at'        => '2026-11-01T09:30:00+00:00',
            'updated_at'        => '2026-11-01T09:30:00+00:00',
        ], self::columns($row));

        self::assertMatchesRegularExpression('/^[0-9a-z]{26}$/D', $row->id);
        self::assertNotSame($state, $row->state_digest);
        self::assertNotSame($nonce, $row->nonce_digest);
        self::assertNotNull($row->code_verifier);
        self::assertNotSame($pkce, $row->code_verifier);
        self::assertStringNotContainsString($pkce, $row->code_verifier);
        self::assertSame($pkce, app(SecretEncrypter::class)->decrypt($row->code_verifier));
    }

    /**
     * The answer carries the reference, redirect and generated verifier once,
     * with `Cache-Control: no-store`.
     *
     * @return void
     */
    public function testTheAnswerCarriesTheGeneratedVerifierOnceWithNoStore(): void
    {
        $result = $this->startFlow();

        self::assertTrue($result->isStarted());
        self::assertNotNull($result->verifier);
        self::assertTrue(Verifier::isWellFormed($result->verifier->reveal()));
        self::assertSame([
            'reference'  => $result->reference?->value,
            'navigation' => ['type' => 'redirect', 'url' => 'https://idp.example.com/authorize?client_id=client-123'],
            'verifier'   => $result->verifier->reveal(),
        ], $result->body());
        self::assertSame(['Cache-Control' => 'no-store'], $result->headers());
        self::assertTrue(RequestReference::isWellFormed((string) $result->reference?->value));
    }

    /**
     * A client's challenge is stored as given, and no verifier is answered.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClientsChallengeIsStoredAndNoVerifierIsAnswered(): void
    {
        $challenge = Verifier::generate()->challenge()->value;

        $result = $this->startFlow(codeChallenge: $challenge);

        self::assertTrue($result->isStarted());
        self::assertNull($result->verifier);
        self::assertSame([
            'reference'  => $result->reference?->value,
            'navigation' => ['type' => 'redirect', 'url' => 'https://idp.example.com/authorize?client_id=client-123'],
        ], $result->body());
        self::assertSame(['Cache-Control' => 'no-store'], $result->headers());
        self::assertSame($challenge, self::onlyRequest()->handoff_challenge);
    }

    /**
     * A posted form navigation is answered, and the driver's SAML id, issuer
     * and `iss` requirement are stored.
     *
     * @return void
     */
    public function testAPostNavigationAndWhatTheDriverAnswersAreKept(): void
    {
        $this->driver->post           = true;
        $this->driver->samlRequestId  = '_a3f9c2e1-request';
        $this->driver->expectedIssuer = 'https://idp.example.com/saml';
        $this->driver->issuerRequired = true;

        $result = $this->startFlow();
        $state  = $this->driver->lastStart()->state->reveal();
        $row    = self::onlyRequest();

        self::assertSame([
            'type'   => 'post',
            'url'    => StartingDriver::URL,
            'fields' => ['SAMLRequest' => 'PHNhbWxwOkF1dGhuUmVxdWVzdC8+', 'RelayState' => $state],
        ], $result->body()['navigation']);
        self::assertTrue($result->navigation?->isPost());
        self::assertSame('_a3f9c2e1-request', $row->saml_request_id);
        self::assertSame('https://idp.example.com/saml', $row->expected_issuer);
        self::assertTrue($row->issuer_required);
    }

    /**
     * Each lifetime and the expiry it gives at 09:30:00.
     *
     * @return iterable<string, array{0: ?int, 1: string}>
     */
    public static function lifetimes(): iterable
    {
        yield 'the default' => [null, '2026-11-01T09:40:00+00:00'];
        yield 'the shortest' => [60, '2026-11-01T09:31:00+00:00'];
        yield 'the longest' => [900, '2026-11-01T09:45:00+00:00'];
    }

    /**
     * The request lives the configured lifetime, ten minutes by default.
     *
     * @param  ?int  $ttl
     * @param  string  $expiresAt
     * @return void
     */
    #[DataProvider('lifetimes')]
    public function testTheRequestLivesTheConfiguredLifetime(?int $ttl, string $expiresAt): void
    {
        if ($ttl !== null) {
            config()->set('sso.authorization_requests.ttl_seconds', $ttl);
        }

        $this->startFlow();

        self::assertSame($expiresAt, self::onlyRequest()->expires_at->toIso8601String());
    }

    /**
     * Each lifetime one past a bound.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function outOfBoundsLifetimes(): iterable
    {
        yield 'one under the shortest' => [59];
        yield 'one over the longest' => [901];
    }

    /**
     * A lifetime outside its bounds fails closed, naming its key and bounds,
     * and stores nothing.
     *
     * @param  int  $ttl
     * @return void
     */
    #[DataProvider('outOfBoundsLifetimes')]
    public function testALifetimeOutsideItsBoundsFailsClosed(int $ttl): void
    {
        config()->set('sso.authorization_requests.ttl_seconds', $ttl);

        try {
            $this->startFlow();
            self::fail('A lifetime outside its bounds was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('sso.authorization_requests.ttl_seconds must be an integer from 60 to 900.', $exception->getMessage());
        }

        self::assertSame(0, AuthorizationRequest::query()->count());
    }

    /**
     * Each misbound start and its message.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: ?\SineMacula\Laravel\Sso\Identities\Caller, 2: string}>
     */
    public static function misboundStarts(): iterable
    {
        $signIn = 'A `sign_in` flow is started with no caller.';
        $link   = 'A `link` flow is started for a caller.';
        $reauth = 'A `reauthenticate` flow is started for a caller, on a session.';

        yield 'sign_in with a caller' => [Purpose::SIGN_IN, new Caller(self::identity()), $signIn];
        yield 'sign_in with a caller on a session' => [Purpose::SIGN_IN, new Caller(self::identity(), 'session-1'), $signIn];
        yield 'link without a caller' => [Purpose::LINK, null, $link];
        yield 'reauthenticate without a caller' => [Purpose::REAUTHENTICATE, null, $reauth];
        yield 'reauthenticate without a session' => [Purpose::REAUTHENTICATE, new Caller(self::identity()), $reauth];
    }

    /**
     * A caller that does not fit the purpose is the application's mistake,
     * refused before anything is counted.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  string  $message
     * @return void
     */
    #[DataProvider('misboundStarts')]
    public function testAMisboundStartIsAnInvalidArgument(Purpose $purpose, ?Caller $caller, string $message): void
    {
        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        try {
            $this->startFlow(purpose: $purpose, caller: $caller);
            self::fail('A misbound start was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
        }

        self::assertSame(0, DB::table(StorageConnection::table('rate_limits.table'))->count());
        self::assertSame([], $this->driver->starts());
        self::assertSame([], $this->freshness->operations());
        self::assertSame(0, AuthorizationRequest::query()->count());
    }

    /**
     * A full limit refuses the start with its wait before admission; another IP
     * address still starts.
     *
     * @return void
     */
    public function testAFullLimitRefusesTheStartWithItsWait(): void
    {
        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        self::assertTrue($this->startFlow()->isStarted());

        $limited = $this->startFlow(application: 'missing');

        self::assertSame(StartStatus::RATE_LIMITED, $limited->status);
        self::assertTrue($limited->isRateLimited());
        self::assertSame(FailureReason::RATE_LIMITED, $limited->reason);
        self::assertSame(60, $limited->retryAfter);
        self::assertSame(['error' => 'rate_limited', 'retry_after' => 60], $limited->body());
        self::assertSame(['Cache-Control' => 'no-store', 'Retry-After' => '60'], $limited->headers());
        self::assertCount(1, $this->driver->starts());
        self::assertSame(1, AuthorizationRequest::query()->count());

        $this->client = new ClientContext('198.51.100.9', null);

        self::assertTrue($this->startFlow()->isStarted());
    }

    /**
     * Rows of `[application, connection, limited, reason]`; a `null` reason
     * means the request is stored.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: bool, 3: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideReports(): iterable
    {
        yield 'started' => ['web', null, false, null];
        yield 'rate limited' => ['web', null, true, FailureReason::RATE_LIMITED];
        yield 'an application not allowed' => ['missing', null, false, FailureReason::APPLICATION_NOT_ALLOWED];
        yield 'an unknown connection' => ['web', self::UNKNOWN_ID, false, FailureReason::CONNECTION_UNAVAILABLE];
    }

    /**
     * A start reports the client it was given, never the served request's.
     *
     * @param  string  $application
     * @param  ?string  $connectionId
     * @param  bool  $limited
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideReports')]
    public function testWhatAStartReportsCarriesTheClientItWasGiven(string $application, ?string $connectionId, bool $limited, ?FailureReason $reason): void
    {
        $this->client = new ClientContext('203.0.113.7', 'Example/1.0');

        if ($limited) {
            config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 1, 'decay_seconds' => 60]);
            $this->startFlow();
        }

        $this->app?->instance('request', Request::create('/', 'POST', server: ['REMOTE_ADDR' => '198.51.100.9', 'HTTP_USER_AGENT' => 'Served/1.0']));
        $this->startRecordingEvents();

        $this->startFlow(application: $application, connectionId: $connectionId);

        $event = $reason === null ? $this->recordedEvents()[0] ?? null : $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, $reason);

        if ($reason === null) {
            self::assertInstanceOf(AuthorizationRequestStarted::class, $event);
        }

        self::assertNotNull($event);
        self::assertSame(['203.0.113.7', 'Example/1.0'], [$event->context()->ip, $event->context()->userAgent]);
    }

    /**
     * A start made for no client counts no IP address, and no limit refuses it.
     *
     * @return void
     */
    public function testAStartForNoClientCountsNoAddress(): void
    {
        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        $this->client = new ClientContext(null, null);

        self::assertTrue($this->startFlow()->isStarted());
        self::assertTrue($this->startFlow()->isStarted());
        self::assertSame(0, DB::table(StorageConnection::table('rate_limits.table'))->count());
    }

    /**
     * Unknown applications and those without external sign-in are refused
     * before the challenge is judged.
     *
     * @return void
     */
    public function testAnApplicationThatIsNotAllowedIsRefused(): void
    {
        foreach (['missing', 'closed', 'Web'] as $application) {
            $this->assertRefused(FailureReason::APPLICATION_NOT_ALLOWED, $this->startFlow(application: $application, codeChallenge: 'not-a-challenge'));
        }

        self::assertSame([], $this->driver->starts());
    }

    /**
     * Each malformed challenge.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function malformedChallenges(): iterable
    {
        yield 'empty' => [''];
        yield 'one character short' => [str_repeat('a', 42)];
        yield 'one character long' => [str_repeat('a', 44)];
        yield 'padded' => [str_repeat('a', 42) . '='];
        yield 'standard base64' => [str_repeat('a', 42) . '+'];
    }

    /**
     * A challenge that is not S256 is refused before the connection is looked
     * up.
     *
     * @param  string  $challenge
     * @return void
     */
    #[DataProvider('malformedChallenges')]
    public function testAMalformedChallengeIsRefused(string $challenge): void
    {
        $this->assertRefused(FailureReason::CHALLENGE_INVALID, $this->startFlow(codeChallenge: $challenge));
        $this->assertRefused(FailureReason::CHALLENGE_INVALID, $this->startFlow(application: 'discovering', connectionId: self::UNKNOWN_ID, codeChallenge: $challenge));

        self::assertSame([], $this->driver->starts());
    }

    /**
     * Unusable connections, including a collation-folded id, are refused
     * without discovery.
     *
     * @return void
     */
    public function testAnUnusableConnectionIsRefusedWithoutDiscovery(): void
    {
        config()->set('sso.features.discovery', true);

        foreach ($this->unusableConnectionIds() as $id) {
            $this->assertRefused(FailureReason::CONNECTION_UNAVAILABLE, $this->startFlow(connectionId: $id));
        }

        self::assertSame([], $this->driver->starts());
    }

    /**
     * With discovery offered but off, an unusable connection is refused too.
     *
     * @return void
     */
    public function testAnUnusableConnectionIsRefusedWhileDiscoveryIsOff(): void
    {
        config()->set('sso.features.discovery', false);

        foreach ($this->unusableConnectionIds() as $id) {
            $this->assertRefused(FailureReason::CONNECTION_UNAVAILABLE, $this->startFlow(application: 'discovering', connectionId: $id));
        }
    }

    /**
     * With discovery on, an unusable connection gets the fallback, a fresh
     * reference and verifier, and nothing stored.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnUnusableConnectionLeadsToTheFallbackWhenDiscoveryIsOffered(): void
    {
        config()->set('sso.features.discovery', true);

        foreach ($this->unusableConnectionIds() as $id) {

            $result = $this->startFlow(application: 'discovering', connectionId: $id);

            self::assertSame(StartStatus::STARTED, $result->status, $id);
            self::assertNotNull($result->reference);
            self::assertNotNull($result->verifier);
            self::assertTrue(RequestReference::isWellFormed($result->reference->value));
            self::assertSame([
                'reference'  => $result->reference->value,
                'navigation' => ['type' => 'redirect', 'url' => self::FALLBACK],
                'verifier'   => $result->verifier->reveal(),
            ], $result->body());
            self::assertSame(['Cache-Control' => 'no-store'], $result->headers());

            $withChallenge = $this->startFlow(application: 'discovering', connectionId: $id, codeChallenge: Verifier::generate()->challenge()->value);

            self::assertTrue($withChallenge->isStarted());
            self::assertNull($withChallenge->verifier);
            self::assertSame(['reference', 'navigation'], array_keys($withChallenge->body()));
        }

        self::assertSame([], $this->driver->starts());
        self::assertSame(0, AuthorizationRequest::query()->count());
    }

    /**
     * A stale `link` is refused after one `sso.link.create` check, without
     * asking the driver.
     *
     * @return void
     */
    public function testAStaleLinkIsRefused(): void
    {
        $this->freshness->answer(FreshnessOutcome::STALE);

        $caller = new Caller(self::identity());

        $this->assertRefused(FailureReason::FRESHNESS_REQUIRED, $this->startFlow(purpose: Purpose::LINK, caller: $caller));

        self::assertSame([FreshnessOperation::LINK_CREATE], $this->freshness->operations());
        self::assertSame([$caller], $this->freshness->callers());
        self::assertSame([], $this->driver->starts());
    }

    /**
     * A fresh `link` stores its identity; a `sign_in` never asks freshness.
     *
     * @return void
     */
    public function testAFreshLinkIsStartedForItsIdentity(): void
    {
        $this->startFlow();

        self::assertSame([], $this->freshness->operations());

        $result = $this->startFlow(purpose: Purpose::LINK, caller: new Caller(self::identity()));
        $row    = AuthorizationRequest::query()->where('reference', $result->reference?->value)->sole();

        self::assertTrue($result->isStarted());
        self::assertSame([FreshnessOperation::LINK_CREATE], $this->freshness->operations());
        self::assertSame(Purpose::LINK, $row->purpose);
        self::assertSame(['App\Models\User', '42', null], [$row->identity_type, $row->identity_id, $row->session_id]);
        self::assertSame(Purpose::LINK, $this->driver->lastStart()->purpose);
    }

    /**
     * A `link` passes its session to freshness only; the request stores the
     * identity alone.
     *
     * @return void
     */
    public function testALinkGivesItsCallersSessionToFreshnessAlone(): void
    {
        $caller = new Caller(self::identity(), 'session-1');
        $result = $this->startFlow(purpose: Purpose::LINK, caller: $caller);
        $row    = AuthorizationRequest::query()->where('reference', $result->reference?->value)->sole();

        self::assertTrue($result->isStarted());
        self::assertSame([$caller], $this->freshness->callers());
        self::assertSame('session-1', $this->freshness->callers()[0]->sessionId);
        self::assertSame(['App\Models\User', '42', null], [$row->identity_type, $row->identity_id, $row->session_id]);

        $this->freshness->answer(FreshnessOutcome::STALE);

        $this->assertRefused(FailureReason::FRESHNESS_REQUIRED, $this->startFlow(purpose: Purpose::LINK, caller: $caller), 1);
        self::assertSame([$caller, $caller], $this->freshness->callers());
    }

    /**
     * A `reauthenticate` is refused by default: the package keeps no sessions.
     *
     * @return void
     */
    public function testAReauthenticationIsRefusedByDefault(): void
    {
        $this->assertRefused(FailureReason::SESSION_INELIGIBLE, $this->startFlow(purpose: Purpose::REAUTHENTICATE, caller: new Caller(self::identity(), 'session-1')));

        self::assertSame([], $this->driver->starts());
    }

    /**
     * A bound session contract decides a `reauthenticate`, asked with identity,
     * session, application and connection.
     *
     * @return void
     */
    public function testABoundSessionContractDecidesAReauthentication(): void
    {
        $sessions = new class implements ReauthenticationSessions {
            /** @var \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding What every question is answered. */
            public SessionStanding $standing = SessionStanding::NOT_SIGNED_IN;

            /** @var list<array{0: \SineMacula\Laravel\Sso\Identities\IdentityReference, 1: string, 2: string, 3: string}> Each question, in order. */
            public array $asked = [];

            /**
             * Record the question and answer the standing set.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  string  $application
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            #[\Override]
            public function standing(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection): SessionStanding
            {
                $this->asked[] = [$identity, $sessionId, $application, $connection->getConnectionId()];

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
                unset($linkId);

                return $this->standing($identity, $sessionId, $application, $connection);
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

        $this->app?->instance(ReauthenticationSessions::class, $sessions);

        $identity = self::identity();
        $session  = str_repeat('s', 255);

        $this->assertRefused(FailureReason::SESSION_INELIGIBLE, $this->startFlow(purpose: Purpose::REAUTHENTICATE, caller: new Caller($identity, $session)));

        self::assertSame([], $this->driver->starts());

        $sessions->standing = SessionStanding::SIGNED_IN;

        $result = $this->startFlow(purpose: Purpose::REAUTHENTICATE, caller: new Caller($identity, $session));
        $row    = self::onlyRequest();

        self::assertTrue($result->isStarted());
        self::assertSame([[$identity, $session, 'web', $this->connection->id], [$identity, $session, 'web', $this->connection->id]], $sessions->asked);
        self::assertSame(Purpose::REAUTHENTICATE, $row->purpose);
        self::assertSame(['App\Models\User', '42', $session], [$row->identity_type, $row->identity_id, $row->session_id]);
        self::assertSame([], $this->freshness->operations());
    }

    /**
     * The session contract is asked about the starting application, so another
     * application's session is ineligible.
     *
     * @return void
     */
    public function testAReauthenticationAsksAboutTheApplicationItIsStartedFor(): void
    {
        $sessions = new RecordingSessions(application: 'web');
        $caller   = new Caller(self::identity(), 'session-1');

        $this->app?->instance(ReauthenticationSessions::class, $sessions);

        $this->assertRefused(FailureReason::SESSION_INELIGIBLE, $this->startFlow('discovering', Purpose::REAUTHENTICATE, caller: $caller));
        self::assertSame([], $this->driver->starts());

        self::assertTrue($this->startFlow('web', Purpose::REAUTHENTICATE, caller: $caller)->isStarted());
        self::assertSame(['discovering', 'web'], array_column($sessions->asked, 2));
    }

    /**
     * A driver that cannot start is refused with its reason, and stores
     * nothing.
     *
     * @return void
     */
    public function testADriverThatCannotStartIsRefusedWithItsReason(): void
    {
        $this->driver->refusal = FailureReason::METADATA_EXPIRED;

        $this->assertRefused(FailureReason::METADATA_EXPIRED, $this->startFlow());

        self::assertCount(1, $this->driver->starts());
    }

    /**
     * Each change to a connection made while the driver starts.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Sso\Models\Connection): mixed}>
     */
    public static function changesWhileStarting(): iterable
    {
        yield 'disabled' => [static fn (Connection $connection): bool => $connection->forceFill(['enabled' => false])->save()];
        yield 'its settings changed' => [static fn (Connection $connection): bool => $connection->forceFill(['settings' => ['issuer' => 'https://other.example.com']])->save()];
        yield 'its secrets changed' => [static fn (Connection $connection): bool => $connection->forceFill(['secrets' => '{"api_secret":"ciphertext"}'])->save()];
        yield 'deleted' => [static fn (Connection $connection): ?bool => $connection->delete()];
        yield 'its trust version raised' => [static fn (Connection $connection): int => Connection::query()->whereKey($connection->id)->increment('trust_version')];
    }

    /**
     * A connection changed or deleted while the driver started is unavailable
     * once the start locks it.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\Connection): mixed  $change
     * @return void
     */
    #[DataProvider('changesWhileStarting')]
    public function testAConnectionChangedWhileTheDriverStartedIsUnavailable(\Closure $change): void
    {
        config()->set('sso.features.discovery', true);

        $connection = $this->connection;

        $this->driver->onStart = static function () use ($change, $connection): void {
            $change($connection);
        };

        $this->assertRefused(FailureReason::CONNECTION_UNAVAILABLE, $this->startFlow());

        self::assertCount(1, $this->driver->starts());

        $other = $this->usableConnection();

        $this->driver->onStart = static function () use ($change, $other): void {
            $change($other);
        };

        $fallback = $this->startFlow(application: 'discovering', connectionId: $other->id);

        self::assertTrue($fallback->isStarted());
        self::assertNotNull($fallback->verifier);
        self::assertSame(['type' => 'redirect', 'url' => self::FALLBACK], $fallback->navigation?->jsonSerialize());
        self::assertCount(2, $this->driver->starts());
        self::assertSame(0, AuthorizationRequest::query()->count());
    }

    /**
     * The request keeps the trust version the start read; an additive change
     * does not stop the store.
     *
     * @return void
     */
    public function testTheRequestKeepsTheTrustVersionTheStartRead(): void
    {
        Connection::query()->whereKey($this->connection->id)->update(['trust_version' => 3]);

        self::assertTrue($this->startFlow()->isStarted());
        self::assertSame(3, self::onlyRequest()->trust_version);
    }

    /**
     * Renaming the connection while the driver started changes nothing the
     * request depends on.
     *
     * @return void
     */
    public function testAConnectionRenamedWhileTheDriverStartedIsStillUsed(): void
    {
        $connection = $this->connection;

        $this->driver->onStart = static function () use ($connection): void {
            $connection->forceFill(['display_name' => 'Renamed'])->save();
        };

        self::assertTrue($this->startFlow()->isStarted());
        self::assertSame(1, AuthorizationRequest::query()->count());
    }

    /**
     * Each stored request raises only its connection's flows version, by one; a
     * refusal raises nothing.
     *
     * @return void
     */
    public function testEachStoredRequestRaisesItsConnectionsFlowsVersionByOne(): void
    {
        $connection = $this->connection;
        $other      = $this->usableConnection();

        self::assertSame([0, 0], self::flowsVersions($connection, $other));

        $this->startFlow();

        self::assertSame([1, 0], self::flowsVersions($connection, $other));

        $this->startFlow();

        self::assertSame([2, 0], self::flowsVersions($connection, $other));

        $this->driver->refusal = FailureReason::METADATA_EXPIRED;

        $this->assertRefused(FailureReason::METADATA_EXPIRED, $this->startFlow(), 2);

        $this->driver->refusal = null;
        $this->driver->onStart = static function () use ($connection): void {
            $connection->forceFill(['settings' => ['issuer' => 'https://other.example.com']])->save();
        };

        $this->assertRefused(FailureReason::CONNECTION_UNAVAILABLE, $this->startFlow(), 2);

        self::assertSame([2, 0], self::flowsVersions($connection, $other));
    }

    /**
     * Maps compare whatever their key order at any depth; a reordered list is a
     * different connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheConnectionIsComparedWhateverTheKeyOrderOfItsMaps(): void
    {
        $application = self::application('web');
        $settings    = ['issuer' => 'https://idp.example.com', 'scopes' => ['openid', 'email'], 'claims' => ['b' => 1, 'a' => ['y' => 1, 'x' => 2]]];

        $this->connection->forceFill(['settings' => $settings])->save();

        $connection = Connection::query()->findOrFail($this->connection->id);

        $connection->setAttribute('settings', ['claims' => ['a' => ['x' => 2, 'y' => 1], 'b' => 1], 'scopes' => ['email', 'openid'], 'issuer' => 'https://idp.example.com']);

        $this->assertRefused(FailureReason::CONNECTION_UNAVAILABLE, $this->service()->begin($application, Purpose::SIGN_IN, $connection, null, null, Clients::browser()));

        $connection->setAttribute('settings', ['claims' => ['a' => ['x' => 2, 'y' => 1], 'b' => 1], 'scopes' => ['openid', 'email'], 'issuer' => 'https://idp.example.com']);

        self::assertTrue($this->service()->begin($application, Purpose::SIGN_IN, $connection, null, null, Clients::browser())->isStarted());
        self::assertSame(1, AuthorizationRequest::query()->count());
    }

    /**
     * A duplicate SAML request id from the driver is a bug: the unique
     * violation propagates.
     *
     * @return void
     */
    public function testADuplicateSamlRequestIdPropagates(): void
    {
        $this->driver->samlRequestId = '_duplicate';

        $this->startFlow();

        try {
            $this->startFlow();
            self::fail('A duplicate SAML request id was stored.');
        } catch (UniqueConstraintViolationException) {
            self::assertSame(1, AuthorizationRequest::query()->count());
        }
    }

    /**
     * `begin()` checks the binding and challenge itself and starts through a
     * connection already found.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testBeginChecksTheBindingAndTheChallengeItself(): void
    {
        $application = self::application('web');

        try {
            $this->service()->begin($application, Purpose::SIGN_IN, $this->connection, null, new Caller(self::identity()), Clients::browser());
            self::fail('A misbound begin was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A `sign_in` flow is started with no caller.', $exception->getMessage());
        }

        $this->assertRefused(
            FailureReason::CHALLENGE_INVALID,
            $this->service()->begin($application, Purpose::SIGN_IN, $this->connection, 'not-a-challenge', null, Clients::browser()),
        );

        $started = $this->service()->begin($application, Purpose::SIGN_IN, $this->connection, null, null, Clients::browser());

        self::assertTrue($started->isStarted());
        self::assertSame($started->reference?->value, self::onlyRequest()->reference);
        self::assertSame(0, DB::table(StorageConnection::table('rate_limits.table'))->count());
    }

    /**
     * `fallback()` leads to the application's fallback, and is a mistake for an
     * application with none.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testFallbackNeedsTheApplicationsFallback(): void
    {
        config()->set('sso.features.discovery', true);

        $result = $this->service()->fallback(self::application('discovering'), true);

        self::assertTrue($result->isStarted());
        self::assertNull($result->verifier);
        self::assertSame(['type' => 'redirect', 'url' => self::FALLBACK], $result->navigation?->jsonSerialize());

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The [web] application has no discovery fallback.');

        $this->service()->fallback(self::application('web'), false);
    }

    /**
     * Assert the start was refused with the reason, stored nothing new, and
     * answered with `no-store`.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $result
     * @param  int  $stored
     * @return void
     */
    private function assertRefused(FailureReason $reason, StartResult $result, int $stored = 0): void
    {
        self::assertSame(StartStatus::REFUSED, $result->status, $reason->value);
        self::assertTrue($result->isRefused());
        self::assertSame($reason, $result->reason);
        self::assertNull($result->reference);
        self::assertNull($result->navigation);
        self::assertNull($result->verifier);
        self::assertSame(['error' => $reason->value], $result->body());
        self::assertSame(['Cache-Control' => 'no-store'], $result->headers());
        self::assertSame($stored, AuthorizationRequest::query()->count());
    }

    /**
     * The flows version of each connection, read again.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  ...$connections
     * @return list<int>
     */
    private static function flowsVersions(Connection ...$connections): array
    {
        return array_values(array_map(static fn (Connection $connection): int => Connection::query()->findOrFail($connection->id)->flows_version, $connections));
    }

    /**
     * Start a flow, a `sign_in` for `web` through the usable connection unless
     * told otherwise.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?string  $connectionId
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Database\QueryException
     */
    private function startFlow(
        string $application = 'web',
        Purpose $purpose = Purpose::SIGN_IN,
        ?string $connectionId = null,
        ?string $codeChallenge = null,
        ?Caller $caller = null,
    ): StartResult {
        return $this->service()->start($application, $purpose, $connectionId ?? $this->connection->id, $this->client, $codeChallenge, $caller);
    }

    /**
     * The service, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Flows\AuthorizationRequestService
     */
    private function service(): AuthorizationRequestService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(AuthorizationRequestService::class);
    }

    /**
     * An enabled connection over the starting driver, complete unless told
     * otherwise.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function usableConnection(array $attributes = []): Connection
    {
        return $this->makeConnection($attributes + [
            'protocol' => StartingDriver::NAME,
            'enabled'  => true,
            'settings' => ['issuer' => 'https://idp.example.com'],
        ]);
    }

    /**
     * The ids of unknown, disabled and incomplete connections, and the usable
     * one's id in upper case.
     *
     * @return list<string>
     */
    private function unusableConnectionIds(): array
    {
        return [
            self::UNKNOWN_ID,
            $this->usableConnection(['enabled' => false])->id,
            $this->usableConnection(['settings' => []])->id,
            strtoupper($this->connection->id),
        ];
    }

    /**
     * The one request stored.
     *
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private static function onlyRequest(): AuthorizationRequest
    {
        return AuthorizationRequest::query()->sole();
    }

    /**
     * The request's columns except its key and encrypted verifier, times as ISO
     * 8601.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $row
     * @return array<string, mixed>
     */
    private static function columns(AuthorizationRequest $row): array
    {
        return [
            'reference'         => $row->reference,
            'state_digest'      => $row->state_digest,
            'purpose'           => $row->purpose,
            'application'       => $row->application,
            'connection_id'     => $row->connection_id,
            'expected_issuer'   => $row->expected_issuer,
            'issuer_required'   => $row->issuer_required,
            'nonce_digest'      => $row->nonce_digest,
            'saml_request_id'   => $row->saml_request_id,
            'handoff_challenge' => $row->handoff_challenge,
            'trust_version'     => $row->trust_version,
            'identity_type'     => $row->identity_type,
            'identity_id'       => $row->identity_id,
            'session_id'        => $row->session_id,
            'expires_at'        => $row->expires_at->toIso8601String(),
            'consumed_at'       => $row->consumed_at?->toIso8601String(),
            'voided_at'         => $row->voided_at?->toIso8601String(),
            'completed_at'      => $row->completed_at?->toIso8601String(),
            'created_at'        => $row->created_at->toIso8601String(),
            'updated_at'        => $row->updated_at->toIso8601String(),
        ];
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
     * The registered application of the name.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Sso\Applications\Application
     */
    private static function application(string $name): Application
    {
        $application = app(ApplicationRegistry::class)->find($name);

        self::assertNotNull($application);

        return $application;
    }
}
