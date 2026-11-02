<?php

declare(strict_types = 1);

namespace Tests\Feature\Flows;

use Carbon\CarbonImmutable;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Oidc\AuthorizationRequests;
use SineMacula\Laravel\Sso\Protocols\Oidc\AuthorizationUrl;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\DumpsValues;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for starting an OIDC flow through the public start service
 * (SSO-5.1, SSO-5.2, SSO-5.4, SSO-5.5, SSO-5.10, SSO-2.4, SSO-7.1), with the
 * fake provider reading the URL as an authorisation endpoint would: it sees
 * exactly the expected parameters; the stored row keeps the digests of the
 * state and the nonce, the PKCE verifier encrypted, the expected issuer,
 * whether `iss` is required and the connection's trust version; the client's
 * challenge and the generated verifier stay apart from the PKCE verifier; a
 * `link` asks freshness and a `reauthenticate` the session contract; each
 * refusal reports one `FlowFailed` and stores nothing; a start reports one
 * `AuthorizationRequestStarted` after it commits; and no protocol value reaches
 * an event, a log or a dump. No start reaches the provider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequests::class)]
#[CoversClass(AuthorizationUrl::class)]
#[CoversClass(AuthorizationRequestService::class)]
final class OidcStartTest extends TestCase
{
    use CapturesLogs, DumpsValues, RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var string The tenant of every connection. */
    private const string TENANT = 'tenant-7';

    /** @var string The IP address every start comes from. */
    private const string IP = '203.0.113.7';

    /** @var string The user agent every start comes from. */
    private const string USER_AGENT = 'ExampleBrowser/1.0';

    /** @var string The session a `reauthenticate` is started on. */
    private const string SESSION = 'session-1';

    /** @var string A client's verifier (RFC 7636, appendix B). */
    private const string CLIENT_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /** @var string The S256 challenge of the client's verifier. */
    private const string CLIENT_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /** @var string A value's form when the package generated it: 43 base64url characters. */
    private const string GENERATED = '/^[A-Za-z0-9_-]{43}$/D';

    /** @var int The stale limit by default, in seconds: 30 days. */
    private const int STALE_LIMIT_SECONDS = 2592000;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract a `link` asks. */
    private RecordingFreshness $freshness;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher, which a start never reaches. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The identity provider. */
    private FakeOpenIdProvider $provider;

    /**
     * Bind a fixed clock, a freshness contract that answers `fresh`, a fake
     * fetcher and a request from the client, switch OIDC on, register the
     * application and the endpoints, create the tables, and record events and
     * logs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock     = new FixedClock('2026-11-01T09:30:00Z');
        $this->freshness = new RecordingFreshness;
        $this->fetcher   = new FakeFetcher;
        $this->provider  = new FakeOpenIdProvider;

        $this->provider->serve($this->fetcher);

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Freshness::class, $this->freshness);
        $this->app?->instance(Fetcher::class, $this->fetcher);
        $this->app?->instance('request', Request::create('/auth/sso/authorization-requests', 'POST', server: [
            'REMOTE_ADDR'     => self::IP,
            'HTTP_USER_AGENT' => self::USER_AGENT,
        ]));

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://api.example.com');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $this->createConnectionTables();
        $this->createFlowTables();
        self::rateLimitsMigration()->up(); // @phpstan-ignore method.notFound

        $this->captureLogs();
        $this->startRecordingEvents();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::rateLimitsMigration()->down(); // @phpstan-ignore method.notFound
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * The provider sees exactly the expected parameters, in order, as a
     * redirect the start made without reaching it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheProviderSeesExactlyTheExpectedParameters(): void
    {
        $connection = $this->oidc();
        $result     = $this->startFlow($connection);
        $url        = (string) $result->navigation?->url();
        $parameters = $this->provider->authorize($url)->parameters();

        self::assertTrue($result->isStarted());
        self::assertTrue((bool) $result->navigation?->isRedirect());
        self::assertSame([
            'response_type'         => 'code',
            'client_id'             => FakeOpenIdProvider::CLIENT_ID,
            'redirect_uri'          => "https://api.example.com/auth/sso/connections/{$connection->id}/callback",
            'scope'                 => 'openid email profile',
            'state'                 => $parameters['state']          ?? null,
            'nonce'                 => $parameters['nonce']          ?? null,
            'code_challenge'        => $parameters['code_challenge'] ?? null,
            'code_challenge_method' => 'S256',
        ], $parameters);
        self::assertSame($this->provider->endpoint('authorization') . '?' . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986), $url);

        foreach (['state', 'nonce', 'code_challenge'] as $name) {
            self::assertMatchesRegularExpression(self::GENERATED, $parameters[$name]);
        }

        self::assertCount(4, array_unique([$parameters['state'], $parameters['nonce'], $parameters['code_challenge'], $result->reference?->value]));

        $this->fetcher->assertNothingFetched();
    }

    /**
     * The stored row keeps the digests of the state and the nonce, never
     * either; the PKCE verifier encrypted, whose challenge is the one sent; the
     * expected issuer, whether `iss` is required, and the connection's trust
     * version; and no SAML request id.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheStoredRowKeepsWhatTheCompletionNeeds(): void
    {
        $connection = $this->oidc(['returns_iss' => true], ['trust_version' => 3]);
        $result     = $this->startFlow($connection);
        $parameters = $this->provider->authorize((string) $result->navigation?->url())->parameters();
        $row        = AuthorizationRequest::query()->sole();
        $stored     = (string) $row->code_verifier;
        $verifier   = app(SecretEncrypter::class)->decrypt($stored);

        self::assertSame([
            $result->reference?->value,
            hash('sha256', $parameters['state']),
            hash('sha256', $parameters['nonce']),
            FakeOpenIdProvider::ISSUER,
            true,
            3,
            $connection->id,
            null,
        ], [
            $row->reference,
            $row->state_digest,
            $row->nonce_digest,
            $row->expected_issuer,
            $row->issuer_required,
            $row->trust_version,
            $row->connection_id,
            $row->saml_request_id,
        ]);

        self::assertMatchesRegularExpression(self::GENERATED, $verifier);
        self::assertSame($parameters['code_challenge'], self::s256($verifier));
        self::assertStringNotContainsString($verifier, $stored);
    }

    /**
     * Rows of `[settings, whether `iss` is required, expected issuer]`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool, 2: string}>
     */
    public static function provideIssuers(): iterable
    {
        yield from [
            'by default'            => [[], false, FakeOpenIdProvider::ISSUER],
            'returning iss'         => [['returns_iss' => true], true, FakeOpenIdProvider::ISSUER],
            'not returning iss'     => [['returns_iss' => false], false, FakeOpenIdProvider::ISSUER],
            'with a trailing slash' => [['issuer' => 'https://op.example.test/tenant/'], false, 'https://op.example.test/tenant/'],
        ];
    }

    /**
     * The row keeps the issuer exactly as configured and whether the provider
     * must return `iss`.
     *
     * @param  array<string, mixed>  $settings
     * @param  bool  $required
     * @param  string  $issuer
     * @return void
     */
    #[DataProvider('provideIssuers')]
    public function testTheRowKeepsTheIssuerAndWhetherItMustReturnIss(array $settings, bool $required, string $issuer): void
    {
        $this->startFlow($this->oidc($settings));

        $row = AuthorizationRequest::query()->sole();

        self::assertSame([$issuer, $required], [$row->expected_issuer, $row->issuer_required]);
    }

    /**
     * A client's own challenge is what the request keeps for its handoff, with
     * no verifier answered, and the provider sees the challenge of the
     * package's own verifier, never the client's.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClientsChallengeStaysApartFromThePkceVerifier(): void
    {
        $result     = $this->startFlow($this->oidc(), Purpose::SIGN_IN, self::CLIENT_CHALLENGE);
        $parameters = $this->provider->authorize((string) $result->navigation?->url())->parameters();
        $row        = AuthorizationRequest::query()->sole();
        $verifier   = app(SecretEncrypter::class)->decrypt((string) $row->code_verifier);

        self::assertNull($result->verifier);
        self::assertSame(self::CLIENT_CHALLENGE, $row->handoff_challenge);
        self::assertNotSame(self::CLIENT_CHALLENGE, $parameters['code_challenge']);
        self::assertNotSame(self::CLIENT_VERIFIER, $verifier);
        self::assertSame($parameters['code_challenge'], self::s256($verifier));
    }

    /**
     * With no client challenge, the verifier the package generates for the
     * client is answered once, its challenge kept for the handoff, and it is
     * neither the PKCE verifier nor the source of what the provider sees.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAGeneratedVerifierStaysApartFromThePkceVerifier(): void
    {
        $result     = $this->startFlow($this->oidc());
        $parameters = $this->provider->authorize((string) $result->navigation?->url())->parameters();
        $row        = AuthorizationRequest::query()->sole();
        $verifier   = app(SecretEncrypter::class)->decrypt((string) $row->code_verifier);

        self::assertNotNull($result->verifier);
        self::assertSame($result->verifier->challenge()->value, $row->handoff_challenge);
        self::assertNotSame($result->verifier->reveal(), $verifier);
        self::assertNotSame($row->handoff_challenge, $parameters['code_challenge']);
        self::assertStringNotContainsString($result->verifier->reveal(), (string) $result->navigation?->url());
    }

    /**
     * A `link` asks the freshness contract, once, and then starts for its
     * identity with no fresh authentication forced; a `sign_in` never asks.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testALinkStartAsksFreshness(): void
    {
        $connection = $this->oidc();

        $this->startFlow($connection);

        self::assertSame([], $this->freshness->operations());

        $result     = $this->startFlow($connection, Purpose::LINK, null, self::identity());
        $parameters = $this->provider->authorize((string) $result->navigation?->url())->parameters();
        $row        = AuthorizationRequest::query()->where('reference', $result->reference?->value)->sole();

        self::assertTrue($result->isStarted());
        self::assertSame([FreshnessOperation::LINK_CREATE], $this->freshness->operations());
        self::assertSame(Purpose::LINK, $row->purpose);
        self::assertSame(['App\Models\User', '42', null], [$row->identity_type, $row->identity_id, $row->session_id]);
        self::assertArrayNotHasKey('prompt', $parameters);
        self::assertArrayNotHasKey('max_age', $parameters);
    }

    /**
     * A stale `link` is refused before any request is made.
     *
     * @return void
     */
    public function testAStaleLinkIsRefused(): void
    {
        $this->freshness->answer(FreshnessOutcome::STALE);

        $result = $this->startFlow($this->oidc(), Purpose::LINK, null, self::identity());

        $this->assertRefusedOnce(FailureReason::FRESHNESS_REQUIRED, $result);
        self::assertSame([FreshnessOperation::LINK_CREATE], $this->freshness->operations());
    }

    /**
     * A `reauthenticate` asks the session contract with exactly the identity,
     * the session and the connection, then forces fresh authentication:
     * `max_age=0` over the connection's, and `prompt=login` over an extra one,
     * the other extra parameters kept.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAReauthenticateStartAsksTheSessionsAndForcesFreshAuthentication(): void
    {
        $sessions   = $this->bindSessions(SessionStanding::SIGNED_IN);
        $identity   = self::identity();
        $connection = $this->oidc(['max_age' => 600, 'extra_parameters' => ['prompt' => 'consent', 'login_hint' => 'person@example.test']]);
        $result     = $this->startFlow($connection, Purpose::REAUTHENTICATE, null, $identity, self::SESSION);
        $parameters = $this->provider->authorize((string) $result->navigation?->url())->parameters();
        $row        = AuthorizationRequest::query()->sole();

        self::assertTrue($result->isStarted());
        self::assertSame([[$identity, self::SESSION, $connection->id]], $sessions->asked);
        self::assertSame([], $this->freshness->operations());
        self::assertSame(['0', 'login', 'person@example.test'], [$parameters['max_age'], $parameters['prompt'], $parameters['login_hint']]);
        self::assertSame(
            ['response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method', 'max_age', 'prompt', 'login_hint'],
            array_keys($parameters),
        );
        self::assertSame(Purpose::REAUTHENTICATE, $row->purpose);
        self::assertSame(['App\Models\User', '42', self::SESSION], [$row->identity_type, $row->identity_id, $row->session_id]);
    }

    /**
     * A `reauthenticate` the session contract does not recognise is refused.
     *
     * @return void
     */
    public function testAReauthenticateOutsideTheSessionIsRefused(): void
    {
        $sessions = $this->bindSessions(SessionStanding::NOT_SIGNED_IN);

        $result = $this->startFlow($this->oidc(), Purpose::REAUTHENTICATE, null, self::identity(), self::SESSION);

        $this->assertRefusedOnce(FailureReason::SESSION_INELIGIBLE, $result);
        self::assertCount(1, $sessions->asked);
    }

    /**
     * A sign in sends the connection's own `max_age` and extra parameters in
     * order, through the same start.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAConnectionsMaxAgeAndExtraParametersAreSent(): void
    {
        $connection = $this->oidc(['max_age' => 600, 'scopes' => ['openid', 'email'], 'extra_parameters' => ['ui_locales' => 'en-GB fr', 'prompt' => 'consent']]);
        $parameters = $this->provider->authorize((string) $this->startFlow($connection)->navigation?->url())->parameters();

        self::assertSame(
            ['openid email', '600', 'en-GB fr', 'consent'],
            [$parameters['scope'], $parameters['max_age'], $parameters['ui_locales'], $parameters['prompt']],
        );
        self::assertSame(['max_age', 'ui_locales', 'prompt'], array_slice(array_keys($parameters), 8));
    }

    /**
     * An authorisation endpoint with a query of its own keeps it, with the
     * request's after it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnAuthorizationEndpointsOwnQueryIsKept(): void
    {
        $endpoint = $this->provider->endpoint('authorization') . '?tenant=acme';
        $result   = $this->startFlow($this->oidc(['authorization_endpoint' => $endpoint]));
        $url      = (string) $result->navigation?->url();

        self::assertStringStartsWith($endpoint . '&response_type=code&client_id=' . FakeOpenIdProvider::CLIENT_ID . '&', $url);
        self::assertSame('acme', $this->provider->authorize($url)->parameter('tenant'));
    }

    /**
     * An authorisation endpoint whose query names a parameter the request sets
     * is refused, reporting one `FlowFailed` and storing nothing.
     *
     * @return void
     */
    public function testAnAuthorizationEndpointNamingAParameterIsRefused(): void
    {
        $result = $this->startFlow($this->oidc(['authorization_endpoint' => $this->provider->endpoint('authorization') . '?state=x']));

        $this->assertRefusedOnce(FailureReason::CONNECTION_UNAVAILABLE, $result);
    }

    /**
     * Rows of `[settings, attributes, whether its secret is set, reason]`: a
     * disabled connection, an incomplete one, and an expired refresh of its
     * discovery document or its JWKS, at the stale limit and past it.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: bool, 3: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideRefusals(): iterable
    {
        $unavailable = FailureReason::CONNECTION_UNAVAILABLE;
        $expired     = FailureReason::METADATA_EXPIRED;
        $jwt         = ['client_authentication' => 'private_key_jwt'];

        yield from [
            'disabled'                          => [[], ['enabled' => false], true, $unavailable],
            'no secret'                         => [[], [], false, $unavailable],
            'private key jwt with no key'       => [$jwt, [], false, $unavailable],
            'private key jwt with a secret'     => [$jwt, [], true, $unavailable],
            'discovery document at the limit'   => [[], ['discovery_age' => self::STALE_LIMIT_SECONDS], true, $expired],
            'discovery document past the limit' => [[], ['discovery_age' => self::STALE_LIMIT_SECONDS + 1], true, $expired],
            'JWKS at the limit'                 => [[], ['discovery_age' => 0, 'jwks_age' => self::STALE_LIMIT_SECONDS], true, $expired],
            'JWKS past the limit'               => [[], ['discovery_age' => 0, 'jwks_age' => self::STALE_LIMIT_SECONDS + 1], true, $expired],
        ];
    }

    /**
     * Each refused connection stores nothing, reaches nothing and reports
     * exactly one `FlowFailed(authorization_request, reason)`.
     *
     * @param  array<string, mixed>  $settings
     * @param  array<string, mixed>  $attributes
     * @param  bool  $secret
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testARefusedConnectionReportsOneFailureAndStoresNothing(array $settings, array $attributes, bool $secret, FailureReason $reason): void
    {
        $result = $this->startFlow($this->oidc($settings, $this->withAges($attributes), $secret));

        $this->assertRefusedOnce($reason, $result);
    }

    /**
     * Rows of `[attributes]`: what a refresh wrote one second inside the stale
     * limit.
     *
     * @return iterable<string, array{0: array<string, int>}>
     */
    public static function provideFreshRefreshes(): iterable
    {
        yield from [
            'the discovery document' => [['discovery_age' => self::STALE_LIMIT_SECONDS - 1]],
            'the JWKS'               => [['discovery_age' => 0, 'jwks_age' => self::STALE_LIMIT_SECONDS - 1]],
        ];
    }

    /**
     * One second inside the stale limit, the start goes on.
     *
     * @param  array<string, int>  $attributes
     * @return void
     */
    #[DataProvider('provideFreshRefreshes')]
    public function testARefreshInsideTheStaleLimitStarts(array $attributes): void
    {
        self::assertTrue($this->startFlow($this->oidc([], $this->withAges($attributes)))->isStarted());
    }

    /**
     * A `private_key_jwt` connection with a current client assertion key and no
     * secret is complete, and starts.
     *
     * @return void
     */
    public function testAPrivateKeyJwtConnectionWithACurrentKeyStarts(): void
    {
        $connection = $this->oidc(['client_authentication' => 'private_key_jwt'], [], false);

        $this->clientKey($connection);

        self::assertTrue($this->startFlow($connection)->isStarted());
        self::assertSame(1, AuthorizationRequest::query()->count());
    }

    /**
     * A start inside a transaction already open on the storage connection is a
     * `LogicException` before anything else: no request, no event.
     *
     * @return void
     */
    public function testAStartInsideATransactionIsALogicException(): void
    {
        $connection = $this->oidc();
        $database   = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        try {
            $this->startFlow($connection);

            self::fail('A start inside a transaction was not refused.');
        } catch (\LogicException $exception) {
            self::assertSame('A start runs outside any transaction on the package\'s storage connection: it calls the protocol driver.', $exception->getMessage());
        } finally {
            $database->rollBack();
        }

        self::assertSame(0, AuthorizationRequest::query()->count());
        $this->assertNoEvents();
    }

    /**
     * A start reports exactly `AuthorizationRequestStarted`, once its
     * transaction has committed and with the request stored, carrying the
     * request's reference as its only flow identifier.
     *
     * @return void
     */
    public function testAStartReportsOnlyStartedAfterItCommits(): void
    {
        /** @var list<array{0: int, 1: int}> $seen */
        $seen = [];

        Event::listen(AuthorizationRequestStarted::class, static function () use (&$seen): void {
            $seen[] = [DB::connection(StorageConnection::name())->transactionLevel(), AuthorizationRequest::query()->count()];
        });

        $connection = $this->oidc();
        $result     = $this->startFlow($connection);

        $this->assertEventSequence([AuthorizationRequestStarted::class]);
        $this->assertNoFailure();

        self::assertSame([[0, 1]], $seen);
        self::assertSame([
            'occurred_at'                 => '2026-11-01T09:30:00.000000Z',
            'ip'                          => self::IP,
            'user_agent'                  => self::USER_AGENT,
            'connection_id'               => $connection->id,
            'tenant_id'                   => self::TENANT,
            'protocol'                    => 'oidc',
            'application'                 => 'web',
            'purpose'                     => 'sign_in',
            'request_reference'           => $result->reference?->value,
            'identity_morph_class'        => null,
            'identity_id'                 => null,
            'acting_identity_morph_class' => null,
            'acting_identity_id'          => null,
            'principal_morph_class'       => null,
            'principal_id'                => null,
            'active_tenant_id'            => null,
            'session_id'                  => null,
            'method'                      => null,
        ], $this->recordedEvents()[0]->context()->toArray());
    }

    /**
     * No state, nonce, verifier, challenge, client secret or extra parameter
     * reaches an event, a log or a dump of the answer, for a start of each
     * purpose and for a refused one.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testNoProtocolValueReachesAnEventALogOrADump(): void
    {
        $this->bindSessions(SessionStanding::SIGNED_IN);

        $connection = $this->oidc(['extra_parameters' => ['login_hint' => 'person@example.test']]);
        $results    = [
            $this->startFlow($connection),
            $this->startFlow($connection, Purpose::SIGN_IN, self::CLIENT_CHALLENGE),
            $this->startFlow($connection, Purpose::LINK, null, self::identity()),
            $this->startFlow($connection, Purpose::REAUTHENTICATE, null, self::identity(), self::SESSION),
        ];

        $this->freshness->answer(FreshnessOutcome::STALE);

        $refused = $this->startFlow($connection, Purpose::LINK, null, self::identity());

        self::assertTrue($refused->isRefused());
        $this->assertEventSequence([
            AuthorizationRequestStarted::class,
            AuthorizationRequestStarted::class,
            AuthorizationRequestStarted::class,
            AuthorizationRequestStarted::class,
            FlowFailed::class,
        ]);

        $needles = [FakeOpenIdProvider::CLIENT_SECRET, 'person@example.test', self::CLIENT_VERIFIER, self::CLIENT_CHALLENGE];

        foreach ($results as $result) {

            $parameters = $this->provider->authorize((string) $result->navigation?->url())->parameters();

            array_push($needles, $parameters['state'], $parameters['nonce'], $parameters['code_challenge']);

            if ($result->verifier !== null) {
                array_push($needles, $result->verifier->reveal(), $result->verifier->challenge()->value);
            }

            self::assertDumpsHideTheParameters($result, $parameters);
        }

        foreach (AuthorizationRequest::query()->get() as $row) {
            $needles[] = app(SecretEncrypter::class)->decrypt((string) $row->code_verifier);
        }

        $this->assertNoEventShows($needles);
        $this->assertNothingLoggedContains(...$needles);
    }

    /**
     * Assert the start was refused for the reason, storing nothing, reaching
     * nothing and reporting exactly one failure of the authorisation request.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $result
     * @return void
     */
    private function assertRefusedOnce(FailureReason $reason, StartResult $result): void
    {
        self::assertTrue($result->isRefused());
        self::assertSame($reason, $result->reason);
        self::assertNull($result->navigation);
        self::assertNull($result->reference);
        self::assertNull($result->verifier);
        self::assertSame(0, AuthorizationRequest::query()->count());

        $this->assertEventSequence([FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, $reason);
        $this->fetcher->assertNothingFetched();
    }

    /**
     * Assert no recorded event shows any of the needles, through its context or
     * any dump of the event.
     *
     * @param  list<string>  $needles
     * @return void
     */
    private function assertNoEventShows(array $needles): void
    {
        foreach ($this->recordedEvents() as $event) {

            $shown = [(string) json_encode($event->context()->toArray(), JSON_UNESCAPED_SLASHES), ...array_values(self::dumps($event))];

            foreach ($needles as $needle) {
                foreach ($shown as $text) {
                    self::assertStringNotContainsString($needle, $text);
                }
            }
        }
    }

    /**
     * Bind a session contract that answers the standing and records what it is
     * asked.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding  $standing
     * @return object{asked: list<array{0: \SineMacula\Laravel\Sso\Identities\IdentityReference, 1: string, 2: string}>}
     */
    private function bindSessions(SessionStanding $standing): object
    {
        $sessions = new class ($standing) implements ReauthenticationSessions {
            /** @var list<array{0: \SineMacula\Laravel\Sso\Identities\IdentityReference, 1: string, 2: string}> Each question, in order. */
            public array $asked = [];

            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding  $standing
             */
            public function __construct(

                /** What every question is answered. */
                private readonly SessionStanding $standing,
            ) {}

            /**
             * Record the question and answer the standing.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            #[\Override]
            public function standing(IdentityReference $identity, string $sessionId, SsoConnection $connection): SessionStanding
            {
                $this->asked[] = [$identity, $sessionId, $connection->getConnectionId()];

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

        $this->app?->instance(ReauthenticationSessions::class, $sessions);

        return $sessions;
    }

    /**
     * Assert that no dump of the answer or its navigation shows the request's
     * state, nonce or challenge.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $result
     * @param  array<string, string>  $parameters
     * @return void
     */
    private static function assertDumpsHideTheParameters(StartResult $result, array $parameters): void
    {
        foreach (['navigation', 'answer'] as $what) {
            foreach (self::dumps($what === 'answer' ? $result : $result->navigation) as $dumper => $dumped) {
                self::assertStringNotContainsString($parameters['state'], $dumped, "{$dumper} of the {$what} shows the state.");
                self::assertStringNotContainsString($parameters['nonce'], $dumped, "{$dumper} of the {$what} shows the nonce.");
                self::assertStringNotContainsString($parameters['code_challenge'], $dumped, "{$dumper} of the {$what} shows the challenge.");
            }
        }
    }

    /**
     * Start a flow for `web` through the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?string  $challenge
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $session
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \LogicException
     */
    private function startFlow(
        Connection $connection,
        Purpose $purpose = Purpose::SIGN_IN,
        ?string $challenge = null,
        ?IdentityReference $identity = null,
        ?string $session = null,
    ): StartResult {
        return app(AuthorizationRequestService::class)->start('web', $purpose, $connection->id, $challenge, $identity, $session);
    }

    /**
     * An enabled OIDC connection to the fake provider, with the settings and
     * attributes given, and its client secret set unless told otherwise.
     *
     * @param  array<string, mixed>  $settings
     * @param  array<string, mixed>  $attributes
     * @param  bool  $secret
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function oidc(array $settings = [], array $attributes = [], bool $secret = true): Connection
    {
        $secrets = $secret ? app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret(FakeOpenIdProvider::CLIENT_SECRET)]) : null;

        return $this->makeConnection([
            'tenant_id' => self::TENANT,
            'protocol'  => 'oidc',
            'enabled'   => true,
            'secrets'   => $secrets,
            'settings'  => [
                'issuer'                 => $this->provider->issuer,
                'authorization_endpoint' => $this->provider->endpoint('authorization'),
                'token_endpoint'         => $this->provider->endpoint('token'),
                'jwks_uri'               => $this->provider->endpoint('jwks'),
                'client_id'              => FakeOpenIdProvider::CLIENT_ID,
                ...$settings,
            ],
            ...$attributes,
        ]);
    }

    /**
     * The attributes with the age of a refresh of the discovery document and of
     * the JWKS, in seconds, as the times they were fetched.
     *
     * @param  array<string, mixed>  $attributes
     * @return array<string, mixed>
     */
    private function withAges(array $attributes): array
    {
        $now = $this->clock->now();

        foreach (['discovery_age' => 'metadata_fetched_at', 'jwks_age' => 'jwks_fetched_at'] as $age => $column) {

            if (is_int($attributes[$age] ?? null)) {
                $attributes[$column] = $now->subSeconds($attributes[$age]);
            }

            unset($attributes[$age]);
        }

        return $attributes;
    }

    /**
     * Store a current client assertion key for the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     */
    private function clientKey(Connection $connection): void
    {
        $certificate = Certificates::ecP256();
        $public      = openssl_pkey_get_public($certificate);
        $details     = $public === false ? false : openssl_pkey_get_details($public);

        self::assertIsArray($details);

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::CLIENT_ASSERTION,
            'state'         => KeyState::CURRENT,
            'key_type'      => KeyType::EC,
            'key_bits'      => 256,
            'certificate'   => $certificate,
            'public_key'    => $details['key'],
            'private_key'   => 'ciphertext',
            'fingerprint'   => (string) openssl_x509_fingerprint($certificate, 'sha256'),
        ])->save();
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
     * `BASE64URL(SHA-256(value))` without padding.
     *
     * @param  string  $value
     * @return string
     */
    private static function s256(string $value): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $value, true)), '+/', '-_'), '=');
    }

    /**
     * The shipped migration of the rate limit counters.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function rateLimitsMigration(): Migration
    {
        return require dirname(__DIR__, 3) . self::RATE_LIMITS_MIGRATION;
    }
}
