<?php

declare(strict_types = 1);

namespace Tests\Feature\Discovery;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Discovery\DiscoveryService;
use SineMacula\Laravel\Sso\Discovery\DomainRouter;
use SineMacula\Laravel\Sso\Discovery\Pacer;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\Enums\StartStatus;
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
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\RateLimiting\CounterKeys;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptScope;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Protocols\StartingDriver;
use Tests\TestCase;

/**
 * Feature tests for starting a flow by email domain (SSO-3.4, SSO-3.5,
 * SSO-11.8, SSO-12.3): a match and a miss answer in the same shape and status,
 * only the navigation's URL differing; every kind of miss leads to the
 * application's fallback with nothing stored; each refusal with its exact
 * reason, in the fixed order; the attempt counted against the IP address and
 * the email's normalised domain; a match's own refusals; no read of anything
 * but the domains, the connections, the counters and, on a match, the requests;
 * and every answer held for at least the least time a discovery start takes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DiscoveryService::class)]
#[CoversClass(DomainRouter::class)]
#[CoversClass(Pacer::class)]
final class DiscoveryServiceTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesDomains;

    /** @var string The IP address every start comes from. */
    private const string IP = '203.0.113.7';

    /** @var string The discovery fallback of the `discovering` application. */
    private const string FALLBACK = 'https://app.example.com/sign-in';

    /** @var string Where a match sends the browser. */
    private const string IDP = StartingDriver::URL . '?client_id=client-123';

    /** @var string An email whose domain routes to the usable connection. */
    private const string MATCH = 'someone@example.com';

    /** @var string An email whose domain routes nowhere. */
    private const string MISS = 'someone@unknown.com';

    /** @var int The least time a discovery start takes in these tests, in milliseconds. */
    private const int FLOOR = 50;

    /** @var \SineMacula\Laravel\Sso\Http\ClientContext The client every start is made for. */
    private ClientContext $client;

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract a `link` asks. */
    private RecordingFreshness $freshness;

    /** @var \Tests\Fixtures\Protocols\StartingDriver The driver the connections run over. */
    private StartingDriver $driver;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The usable connection `example.com` routes to. */
    private Connection $connection;

    /**
     * Bind a fixed clock, a freshness contract that answers `fresh` and a
     * request from the IP address, turn discovery on, register the applications
     * and the driver, create the tables, a usable connection and its verified
     * domain.
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
        $this->client = new ClientContext(self::IP, null);

        config()->set('sso.features.oidc', true);
        config()->set('sso.features.discovery', true);
        config()->set('sso.discovery.minimum_duration_milliseconds', self::FLOOR);
        config()->set('sso.applications', [
            'web'         => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
            'closed'      => ['redirect_uri' => 'https://closed.example.com/sso', 'discovery' => ['enabled' => true, 'fallback_url' => self::FALLBACK]],
            'discovering' => [
                'redirect_uri'     => 'https://app.example.com/sso',
                'external_sign_in' => true,
                'discovery'        => ['enabled' => true, 'fallback_url' => self::FALLBACK],
            ],
        ]);

        $driver = $this->driver;

        app(ProtocolManager::class)->extend(StartingDriver::NAME, fn (): StartingDriver => $driver);

        $this->usePackageTables();

        $this->connection = $this->usableConnection(['tenant_id' => 'tenant-7']);

        $this->makeDomain($this->connection, 'example.com', ['state' => DomainState::VERIFIED]);
    }

    /**
     * A match and a miss on the same inputs answer the same status, the same
     * body keys with a verifier, a reference of the same form, a redirect, and
     * the same headers; only the URL differs. The match stores its request and
     * the miss stores nothing.
     *
     * @return void
     */
    public function testAMatchAndAMissAnswerInTheSameShape(): void
    {
        $match = $this->discover(self::MATCH);
        $miss  = $this->discover(self::MISS);

        self::assertSame(StartStatus::STARTED, $match->status);
        self::assertSame(StartStatus::STARTED, $miss->status);
        self::assertSame(['reference', 'navigation', 'verifier'], array_keys($match->body()));
        self::assertSame(['reference', 'navigation', 'verifier'], array_keys($miss->body()));
        self::assertSame(['type' => 'redirect', 'url' => self::IDP], $match->body()['navigation']);
        self::assertSame(['type' => 'redirect', 'url' => self::FALLBACK], $miss->body()['navigation']);
        self::assertSame(['Cache-Control' => 'no-store'], $match->headers());
        self::assertSame(['Cache-Control' => 'no-store'], $miss->headers());

        foreach ([$match, $miss] as $result) {
            self::assertNotNull($result->reference);
            self::assertNotNull($result->verifier);
            self::assertTrue(RequestReference::isWellFormed($result->reference->value));
            self::assertSame(32, strlen($result->reference->value));
            self::assertTrue(Verifier::isWellFormed($result->verifier->reveal()));
            self::assertSame(43, strlen($result->verifier->reveal()));
        }

        $stored = AuthorizationRequest::query()->sole();

        self::assertSame([$match->reference?->value, $this->connection->id, 'discovering'], [$stored->reference, $stored->connection_id, $stored->application]);
        self::assertSame($match->verifier?->challenge()->value, $stored->handoff_challenge);
        self::assertCount(1, $this->driver->starts());
    }

    /**
     * With the client's challenge, a match and a miss both answer the reference
     * and the navigation alone, and the match keeps the challenge.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testWithAChallengeNeitherAnswersAVerifier(): void
    {
        $challenge = Verifier::generate()->challenge()->value;

        $match = $this->discover(self::MATCH, codeChallenge: $challenge);
        $miss  = $this->discover(self::MISS, codeChallenge: $challenge);

        self::assertSame([StartStatus::STARTED, StartStatus::STARTED], [$match->status, $miss->status]);
        self::assertSame(['reference', 'navigation'], array_keys($match->body()));
        self::assertSame(['reference', 'navigation'], array_keys($miss->body()));
        self::assertNull($match->verifier);
        self::assertNull($miss->verifier);
        self::assertSame(['redirect', 'redirect'], [$match->navigation?->jsonSerialize()['type'], $miss->navigation?->jsonSerialize()['type']]);
        self::assertSame($challenge, AuthorizationRequest::query()->sole()->handoff_challenge);
    }

    /**
     * Two misses answer two different references, neither naming a request.
     *
     * @return void
     */
    public function testEachMissAnswersAFreshReference(): void
    {
        $first  = $this->discover(self::MISS);
        $second = $this->discover(self::MISS);

        self::assertNotSame($first->reference?->value, $second->reference?->value);
        self::assertNotSame($first->verifier?->reveal(), $second->verifier?->reveal());
        self::assertSame(0, AuthorizationRequest::query()->count());
    }

    /**
     * Each kind of miss: an unknown, pending, lapsed or past-grace domain, a
     * disabled or incomplete connection, and an email with no domain that
     * normalises.
     *
     * @return void
     */
    public function testEveryKindOfMissLeadsToTheFallback(): void
    {
        $this->makeDomain($this->usableConnection(), 'pending.com');
        $this->makeDomain($this->usableConnection(), 'lapsed.com', ['state' => DomainState::LAPSED, 'lapsed_at' => CarbonImmutable::parse('2026-10-31T09:30:00Z')]);
        $this->makeDomain($this->usableConnection(), 'past-grace.com', ['state' => DomainState::VERIFIED, 'lapses_at' => CarbonImmutable::parse('2026-11-01T09:30:00Z')]);
        $this->makeDomain($this->usableConnection(['enabled' => false]), 'disabled.com', ['state' => DomainState::VERIFIED]);
        $this->makeDomain($this->usableConnection(['settings' => []]), 'incomplete.com', ['state' => DomainState::VERIFIED]);

        $emails = [
            self::MISS, 'someone@pending.com', 'someone@lapsed.com', 'someone@past-grace.com', 'someone@disabled.com', 'someone@incomplete.com',
            'someone@localhost', 'someone@', 'example.com', 'someone@sub.example.com',
        ];

        foreach ($emails as $email) {

            $result = $this->discover($email);

            self::assertSame(StartStatus::STARTED, $result->status, $email);
            self::assertSame(['reference', 'navigation', 'verifier'], array_keys($result->body()), $email);
            self::assertSame(['type' => 'redirect', 'url' => self::FALLBACK], $result->body()['navigation'], $email);
        }

        self::assertSame([], $this->driver->starts());
        self::assertSame(0, AuthorizationRequest::query()->count());
    }

    /**
     * A discovery start called inside the caller's transaction on the storage
     * connection is refused before anything else, for a match and a miss alike:
     * no attempt counted, no driver asked and no request stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStartInsideATransactionIsRefusedBeforeAnythingElse(): void
    {
        $subjects = $this->recordAttempts();
        $database = DB::connection(StorageConnection::name());
        $refusals = [];

        $database->beginTransaction();

        foreach ([self::MATCH, self::MISS] as $email) {

            try {
                $this->service()->start('discovering', Purpose::SIGN_IN, $email, Clients::browser());
            } catch (\LogicException $exception) {
                $refusals[] = $exception->getMessage();
            }
        }

        $database->rollBack();

        $message = 'A discovery start runs outside any transaction on the package\'s storage connection: it may call the protocol driver.';

        self::assertSame([$message, $message], $refusals);
        self::assertCount(0, $subjects);
        self::assertSame([], $this->driver->starts());
        self::assertSame(0, AuthorizationRequest::query()->count());
        self::assertTrue($this->discover(self::MATCH)->isStarted());
    }

    /**
     * A full limit refuses with its wait, before the application is admitted,
     * and is held like any answer.
     *
     * @return void
     */
    public function testAFullLimitIsRateLimited(): void
    {
        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        self::assertTrue($this->discover(self::MATCH)->isStarted());

        $limited = $this->discover(self::MATCH, application: 'missing');

        self::assertSame(StartStatus::RATE_LIMITED, $limited->status);
        self::assertSame(FailureReason::RATE_LIMITED, $limited->reason);
        self::assertSame(60, $limited->retryAfter);
        self::assertSame(['error' => 'rate_limited', 'retry_after' => 60], $limited->body());
        self::assertSame(['Cache-Control' => 'no-store', 'Retry-After' => '60'], $limited->headers());
        self::assertCount(1, $this->driver->starts());
    }

    /**
     * Starts are counted per email domain, in its normalised form, whatever IP
     * address they come from: the domain's counter is the one keyed by
     * `example.com`, and another domain is counted apart.
     *
     * @return void
     */
    public function testStartsAreCountedPerEmailDomain(): void
    {
        config()->set('sso.rate_limits.authorization_request.per_email_domain', ['max' => 1, 'decay_seconds' => 60]);

        self::assertTrue($this->discover('first@example.com')->isStarted());

        $this->client = new ClientContext('198.51.100.9', null);

        $limited = $this->discover('second@EXAMPLE.com.');

        self::assertTrue($limited->isRateLimited());
        self::assertSame(60, $limited->retryAfter);
        self::assertTrue($this->discover(self::MISS)->isStarted());

        $key = app(CounterKeys::class)->counter(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_EMAIL_DOMAIN, 'example.com');

        $hits = DB::table(StorageConnection::table('rate_limits.table'))->where('key', $key)->value('hits');

        self::assertIsNumeric($hits);
        self::assertSame(1, (int) $hits);
        self::assertCount(1, $this->driver->starts());
    }

    /**
     * Each email and what its start is counted against, with a request from the
     * IP address.
     *
     * @return iterable<string, array{0: string, 1: array<string, string>}>
     */
    public static function countedSubjects(): iterable
    {
        yield 'a domain' => [self::MATCH, ['per_ip' => self::IP, 'per_email_domain' => 'example.com']];
        yield 'an IDNA domain in upper case' => ['Someone@BÜCHER.Example.COM.', ['per_ip' => self::IP, 'per_email_domain' => 'xn--bcher-kva.example.com']];
        yield 'the last @' => ['someone@other.com@example.com', ['per_ip' => self::IP, 'per_email_domain' => 'example.com']];
        yield 'a domain that does not normalise' => ['someone@localhost', ['per_ip' => self::IP]];
        yield 'no @' => ['example.com', ['per_ip' => self::IP]];
    }

    /**
     * The attempt is counted against the IP address and the email's normalised
     * domain, never the email, and not the domain when it does not normalise.
     *
     * @param  string  $email
     * @param  array<string, string>  $counted
     * @return void
     */
    #[DataProvider('countedSubjects')]
    public function testTheAttemptIsCountedAgainstTheNormalizedDomain(string $email, array $counted): void
    {
        $subjects = $this->recordAttempts();

        $this->discover($email);

        self::assertCount(1, $subjects);

        $subject = $subjects[0];

        self::assertNotNull($subject);
        self::assertSame(AttemptFlow::AUTHORIZATION_REQUEST, $subject->flow);
        self::assertSame($counted, $subject->counted());
    }

    /**
     * Rows of `[email, application, limited, reason]`: each way a discovery
     * start reports, `null` reason for a match that stores its request.
     *
     * @return iterable<string, array{0: string, 1: string, 2: bool, 3: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideReports(): iterable
    {
        yield 'a match' => [self::MATCH, 'discovering', false, null];
        yield 'rate limited' => [self::MATCH, 'discovering', true, FailureReason::RATE_LIMITED];
        yield 'no match' => [self::MISS, 'discovering', false, FailureReason::DISCOVERY_NO_MATCH];
        yield 'an application not allowed' => [self::MATCH, 'missing', false, FailureReason::APPLICATION_NOT_ALLOWED];
    }

    /**
     * What a discovery start reports carries the IP address and user agent of
     * the client it was given, never the request's being served:
     * `AuthorizationRequestStarted` for a match, and exactly one `FlowFailed`
     * for a miss or a refusal.
     *
     * @param  string  $email
     * @param  string  $application
     * @param  bool  $limited
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideReports')]
    public function testWhatADiscoveryStartReportsCarriesTheClientItWasGiven(string $email, string $application, bool $limited, ?FailureReason $reason): void
    {
        $this->client = new ClientContext(self::IP, 'Example/1.0');

        if ($limited) {
            config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 1, 'decay_seconds' => 60]);
            $this->discover(self::MISS);
        }

        $this->app?->instance('request', Request::create('/', 'POST', server: ['REMOTE_ADDR' => '198.51.100.9', 'HTTP_USER_AGENT' => 'Served/1.0']));
        $this->startRecordingEvents();

        $this->discover($email, application: $application);

        $event = $reason === null ? $this->recordedEvents()[0] ?? null : $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, $reason);

        if ($reason === null) {
            self::assertInstanceOf(AuthorizationRequestStarted::class, $event);
        }

        self::assertNotNull($event);
        self::assertSame([self::IP, 'Example/1.0'], [$event->context()->ip, $event->context()->userAgent]);
    }

    /**
     * A start made for no client counts no IP address, so only the domain is
     * counted.
     *
     * @return void
     */
    public function testAStartForNoClientCountsTheDomainAlone(): void
    {
        $subjects = $this->recordAttempts();

        $this->client = new ClientContext(null, null);

        self::assertTrue($this->discover(self::MATCH)->isStarted());
        self::assertCount(1, $subjects);

        $subject = $subjects[0];

        self::assertNotNull($subject);
        self::assertSame(['per_email_domain' => 'example.com'], $subject->counted());
    }

    /**
     * An unknown application and one that does not allow external sign-in are
     * refused alike, before discovery or the challenge is judged.
     *
     * @return void
     */
    public function testAnApplicationThatIsNotAllowedIsRefused(): void
    {
        foreach (['missing', 'closed', 'Discovering'] as $application) {
            $this->assertRefused(FailureReason::APPLICATION_NOT_ALLOWED, $this->discover(self::MATCH, application: $application, codeChallenge: 'not-a-challenge'));
        }

        self::assertSame([], $this->driver->starts());
    }

    /**
     * An application that does not offer discovery is refused, before the
     * challenge is judged.
     *
     * @return void
     */
    public function testAnApplicationThatDoesNotOfferDiscoveryIsRefused(): void
    {
        $this->assertRefused(FailureReason::FEATURE_DISABLED, $this->discover(self::MATCH, application: 'web'));
        $this->assertRefused(FailureReason::FEATURE_DISABLED, $this->discover(self::MISS, application: 'web', codeChallenge: 'not-a-challenge'));

        self::assertSame([], $this->driver->starts());
    }

    /**
     * With the `discovery` feature off, an application that offers discovery is
     * refused too.
     *
     * @return void
     */
    public function testDiscoveryIsRefusedWhileTheFeatureIsOff(): void
    {
        config()->set('sso.features.discovery', false);

        $this->assertRefused(FailureReason::FEATURE_DISABLED, $this->discover(self::MATCH));
        $this->assertRefused(FailureReason::FEATURE_DISABLED, $this->discover(self::MISS, codeChallenge: 'not-a-challenge'));

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
     * A malformed challenge is refused for a match and a miss alike, before the
     * email is routed.
     *
     * @param  string  $challenge
     * @return void
     */
    #[DataProvider('malformedChallenges')]
    public function testAMalformedChallengeIsRefused(string $challenge): void
    {
        $queries = $this->recordQueries();
        $match   = $this->discover(self::MATCH, codeChallenge: $challenge);
        $miss    = $this->discover(self::MISS, codeChallenge: $challenge);

        // Read before the assertions below, which count the requests themselves
        self::assertSame([StorageConnection::table('rate_limits.table')], self::tablesOf($queries));

        $this->assertRefused(FailureReason::CHALLENGE_INVALID, $match);
        $this->assertRefused(FailureReason::CHALLENGE_INVALID, $miss);
        self::assertSame([], $this->driver->starts());
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
     * A caller that does not fit the purpose is application code's mistake,
     * refused before anything is counted or read.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('misboundStarts')]
    public function testAMisboundStartIsAnInvalidArgument(Purpose $purpose, ?Caller $caller, string $message): void
    {
        $queries = $this->recordQueries();

        try {
            $this->service()->start('discovering', $purpose, self::MATCH, Clients::browser(), null, $caller);
            self::fail('A misbound start was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
        }

        self::assertSame([], $queries->getArrayCopy());
        self::assertSame([], $this->driver->starts());
        self::assertSame([], $this->freshness->operations());
    }

    /**
     * A session id of 1 and of 255 bytes fits a `reauthenticate`: it is
     * started, and refused only by the default session contract.
     *
     * @return void
     */
    public function testASessionIdAtEachBoundFits(): void
    {
        foreach (['s', str_repeat('s', 255)] as $sessionId) {
            $this->assertRefused(FailureReason::SESSION_INELIGIBLE, $this->discover(self::MATCH, Purpose::REAUTHENTICATE, identity: self::identity(), sessionId: $sessionId));
        }
    }

    /**
     * A match whose `link` comes from a stale caller is refused with
     * `freshness_required`, the freshness contract asked once.
     *
     * @return void
     */
    public function testAStaleLinkThatMatchesIsRefused(): void
    {
        $this->freshness->answer(FreshnessOutcome::STALE);

        $this->assertRefused(FailureReason::FRESHNESS_REQUIRED, $this->discover(self::MATCH, Purpose::LINK, identity: self::identity()));

        self::assertSame([FreshnessOperation::LINK_CREATE], $this->freshness->operations());
        self::assertSame([], $this->driver->starts());
    }

    /**
     * A match whose `link` comes from a fresh caller is started for its
     * identity alone, the session the caller gave asked about by freshness and
     * not stored; a miss for a `link` asks nothing and leads to the fallback.
     *
     * @return void
     */
    public function testAFreshLinkThatMatchesIsStartedForItsIdentity(): void
    {
        $miss = $this->discover(self::MISS, Purpose::LINK, identity: self::identity());

        self::assertSame(['type' => 'redirect', 'url' => self::FALLBACK], $miss->body()['navigation']);
        self::assertSame([], $this->freshness->operations());

        $match = $this->discover(self::MATCH, Purpose::LINK, identity: self::identity(), sessionId: 'session-1');
        $row   = AuthorizationRequest::query()->sole();

        self::assertTrue($match->isStarted());
        self::assertSame([FreshnessOperation::LINK_CREATE], $this->freshness->operations());
        self::assertSame('session-1', $this->freshness->callers()[0]?->sessionId);
        self::assertSame([Purpose::LINK, 'App\Models\User', '42', null], [$row->purpose, $row->identity_type, $row->identity_id, $row->session_id]);
    }

    /**
     * A match whose driver cannot start is refused with the driver's reason.
     *
     * @return void
     */
    public function testAMatchWhoseDriverCannotStartIsRefused(): void
    {
        $this->driver->refusal = FailureReason::METADATA_EXPIRED;

        $this->assertRefused(FailureReason::METADATA_EXPIRED, $this->discover(self::MATCH));

        self::assertCount(1, $this->driver->starts());
    }

    /**
     * A match whose connection is disabled while the driver starts leads to the
     * fallback, in the same shape, and stores nothing.
     *
     * @return void
     */
    public function testAMatchDisabledWhileStartingLeadsToTheFallback(): void
    {
        $connection = $this->connection;

        $this->driver->onStart = static function () use ($connection): void {
            $connection->forceFill(['enabled' => false])->save();
        };

        $result = $this->discover(self::MATCH);

        self::assertSame(StartStatus::STARTED, $result->status);
        self::assertSame(['reference', 'navigation', 'verifier'], array_keys($result->body()));
        self::assertSame(['type' => 'redirect', 'url' => self::FALLBACK], $result->body()['navigation']);
        self::assertSame(0, AuthorizationRequest::query()->count());
    }

    /**
     * Discovery never looks up a user: a miss reads the counters and the
     * domains, a miss on an unusable connection the connections too, and a
     * match also writes the authorisation request, and nothing else.
     *
     * @return void
     */
    public function testNoUserIsLookedUp(): void
    {
        $this->makeDomain($this->usableConnection(['enabled' => false]), 'disabled.com', ['state' => DomainState::VERIFIED]);

        $limits      = StorageConnection::table('rate_limits.table');
        $domains     = StorageConnection::table('domains.table');
        $connections = StorageConnection::table('connections.table');
        $requests    = StorageConnection::table('authorization_requests.table');

        $miss = $this->recordQueries();
        $this->discover(self::MISS);

        self::assertSame(self::sorted([$limits, $domains]), self::tablesOf($miss));

        $unusable = $this->recordQueries();
        $this->discover('someone@disabled.com');

        self::assertSame(self::sorted([$limits, $domains, $connections]), self::tablesOf($unusable));

        $match = $this->recordQueries();
        $this->discover(self::MATCH);

        self::assertSame(self::sorted([$limits, $domains, $connections, $requests]), self::tablesOf($match));
    }

    /**
     * An application that offers discovery while the feature is on needs its
     * fallback (SSO-12.3): `[applications]` refuses its absence at boot, as
     * `ApplicationsCheckTest` shows, and a start fails closed with the same
     * message.
     *
     * @return void
     */
    public function testAnApplicationWithoutItsFallbackFailsClosed(): void
    {
        config()->set('sso.applications.discovering.discovery', ['enabled' => true]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`sso.applications.discovering.discovery.fallback_url` must be an exact redirect URI');

        $this->service()->start('discovering', Purpose::SIGN_IN, self::MATCH, Clients::browser());
    }

    /**
     * Assert the start was refused with the reason, wrote no request, and
     * answers the error with `Cache-Control: no-store`.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $result
     * @return void
     */
    private function assertRefused(FailureReason $reason, StartResult $result): void
    {
        self::assertSame(StartStatus::REFUSED, $result->status, $reason->value);
        self::assertSame($reason, $result->reason);
        self::assertNull($result->reference);
        self::assertNull($result->navigation);
        self::assertNull($result->verifier);
        self::assertSame(['error' => $reason->value], $result->body());
        self::assertSame(['Cache-Control' => 'no-store'], $result->headers());
        self::assertSame(0, AuthorizationRequest::query()->count());
    }

    /**
     * Start a flow by email, a `sign_in` for `discovering` unless told
     * otherwise, and assert the answer took at least the least time a discovery
     * start takes.
     *
     * @param  string  $email
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  ?string  $codeChallenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \Throwable
     */
    private function discover(
        string $email,
        Purpose $purpose = Purpose::SIGN_IN,
        string $application = 'discovering',
        ?string $codeChallenge = null,
        ?IdentityReference $identity = null,
        ?string $sessionId = null,
    ): StartResult {
        $startedAt = (int) hrtime(true);
        $result    = $this->service()->start($application, $purpose, $email, $this->client, $codeChallenge, $identity === null ? null : new Caller($identity, $sessionId));
        $took      = (int) hrtime(true) - $startedAt;

        self::assertGreaterThanOrEqual(self::FLOOR * 1000000, $took, 'The answer came before the least time a discovery start takes.');

        return $result;
    }

    /**
     * The service, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Discovery\DiscoveryService
     */
    private function service(): DiscoveryService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DiscoveryService::class);
    }

    /**
     * Bind a limiter that allows every attempt and records its subject.
     *
     * @return \ArrayObject<int, \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject>
     */
    private function recordAttempts(): \ArrayObject
    {
        /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject> $subjects */
        $subjects = new \ArrayObject;

        $this->app?->instance(AttemptLimiter::class, new readonly class ($subjects) implements AttemptLimiter {
            /**
             * Constructor.
             *
             * @param  \ArrayObject<int, \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject>  $subjects
             */
            public function __construct(

                /** Every subject attempted, in order. */
                private \ArrayObject $subjects,
            ) {}

            /**
             * Record the subject and allow it.
             *
             * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject  $subject
             * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptResult
             */
            #[\Override]
            public function attempt(AttemptSubject $subject): AttemptResult
            {
                $this->subjects->append($subject);

                return AttemptResult::allowed();
            }
        });

        return $subjects;
    }

    /**
     * Record the SQL of every statement run from now on.
     *
     * @return \ArrayObject<int, string>
     */
    private function recordQueries(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $queries */
        $queries = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($queries): void {
            $queries->append($query->sql);
        });

        return $queries;
    }

    /**
     * The tables the statements read or wrote, each once, in order of name.
     *
     * @param  \ArrayObject<int, string>  $queries
     * @return list<string>
     */
    private static function tablesOf(\ArrayObject $queries): array
    {
        $tables = [];

        foreach ($queries as $sql) {

            preg_match_all('/\b(?:from|into|update|join)\s+[`"]?([A-Za-z0-9_]+)[`"]?/i', $sql, $matches);

            array_push($tables, ...$matches[1]);
        }

        return self::sorted($tables);
    }

    /**
     * The names, each once, in order.
     *
     * @param  list<string>  $names
     * @return list<string>
     */
    private static function sorted(array $names): array
    {
        $unique = array_values(array_unique($names));

        sort($unique);

        return $unique;
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
     * The identity a `link` or a `reauthenticate` is started for.
     *
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    private static function identity(): IdentityReference
    {
        return new IdentityReference('App\Models\User', '42');
    }
}
