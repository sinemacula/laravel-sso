<?php

declare(strict_types = 1);

namespace Tests\Integration\Standalone;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Composer\Autoload\ClassLoader;
use Illuminate\Foundation\Application;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;
use SineMacula\Laravel\Sso\Console\ExpiringKeysCommand;
use SineMacula\Laravel\Sso\Console\PruneCommand;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Discovery\DiscoveryService;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\ConnectionDisabled;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Freshness\RefusingFreshness;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Models\RateLimit;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneKind;
use SineMacula\Laravel\Sso\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Sso\Responses\CompletionResponse;
use SineMacula\Laravel\Sso\Revocation\NoSessionRevocation;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\FlowRoutes;
use Tests\Concerns\MakesPrunableRows;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesUnreliableCache;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\StandaloneTestCase;

/**
 * What the package does alone (FEATURES "No dependency on a sibling": no
 * dependency, useful alone, sensible behaviour alone, routes are the
 * application's): nothing bound but what the provider binds, the real drivers
 * against the fake providers, and the package's own storage, transactions and
 * commands. Defaults are not all refusals, so each of these is what the default
 * deliberately does.
 *
 * Only the outside world is faked: an OIDC completion's token request goes to a
 * `FakeFetcher`, which is the one seam a test here replaces, and says so. A
 * test of what a default deliberately does not do (revoking a session, with a
 * change no default caller is fresh enough to make) replaces `Freshness` to
 * reach it, and says so too. What a default refuses is
 * `DefaultBindingsRefusalsTest`'s.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoServiceProvider::class)]
#[CoversClass(NoLinks::class)]
#[CoversClass(DatabaseHandoffStore::class)]
#[CoversClass(DatabaseSingleUseStore::class)]
#[CoversClass(DatabaseAttemptLimiter::class)]
#[CoversClass(NoSessionRevocation::class)]
#[CoversClass(DatabaseEnforcement::class)]
#[CoversClass(DiscoveryService::class)]
#[CoversClass(ServiceProviderDescriptions::class)]
#[CoversClass(PruneCommand::class)]
#[CoversClass(ExpiringKeysCommand::class)]
final class DefaultBindingsFlowsTest extends StandaloneTestCase
{
    use FlowRoutes, MakesPrunableRows, RecordsEventSequences, UsesUnreliableCache;

    /** @var string The tenant of every connection. */
    private const string TENANT = 'tenant-1';

    /** @var string A protocol's name, as a row of the data provider gives it. */
    private const string SAML = 'saml2';

    /** @var string A protocol's name, as a row of the data provider gives it. */
    private const string OIDC = 'oidc';

    /** @var list<string> The namespaces of the packages a sibling's classes live under. */
    private const array SIBLING_NAMESPACES = ['SineMacula\Laravel\Authentication\\', 'SineMacula\Laravel\Mfa\\', 'SineMacula\Laravel\Iam\\'];

    /** @var list<string> What each sibling would register, had it been installed. */
    private const array SIBLING_CLASSES = [
        'SineMacula\Laravel\Authentication\AuthenticationServiceProvider',
        'SineMacula\Laravel\Mfa\MfaServiceProvider',
        'SineMacula\Laravel\Iam\IamServiceProvider',
    ];

    /**
     * Stop Laravel's clock, which the default clock follows, configure the
     * protocols, the endpoints and the applications, create the tables and the
     * routes an application adds, and record events. Nothing is bound.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(CarbonImmutable::parse(self::FLOW_NOW));

        $this->flowClock    = new FixedClock(self::FLOW_NOW);
        $this->flowFetcher  = new FakeFetcher;
        $this->flowSessions = new RecordingSessions;

        config()->set('app.debug', false);
        config()->set('sso.features.saml2', true);
        config()->set('sso.features.oidc', true);
        config()->set('sso.features.discovery', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.discovery.minimum_duration_milliseconds', 50);
        config()->set('sso.applications', [
            self::FLOW_APPLICATION        => ['redirect_uri' => self::FLOW_REDIRECT_URI, 'external_sign_in' => true],
            self::DISCOVERING_APPLICATION => [
                'redirect_uri'     => self::FLOW_REDIRECT_URI,
                'external_sign_in' => true,
                'discovery'        => ['enabled' => true, 'fallback_url' => self::FLOW_FALLBACK_URL],
            ],
        ]);

        $this->assertStandalone();
        $this->createEveryTable();
        $this->registerFlowRoutes();
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
        $this->dropEveryTable();

        parent::tearDown();
    }

    /**
     * No sibling is reachable at run time: none of its configuration, none of
     * its classes, and nothing that would autoload one.
     *
     * @return void
     */
    public function testNoSiblingIsReachableAtRunTime(): void
    {
        $this->assertStandalone();

        foreach (['authentication', 'mfa', 'iam'] as $key) {
            self::assertFalse(config()->has($key), "The application holds configuration under [{$key}].");
        }

        self::assertSame([], array_values(array_filter(self::SIBLING_CLASSES, class_exists(...))), 'A sibling\'s class autoloads.');

        foreach (ClassLoader::getRegisteredLoaders() as $loader) {
            self::assertSame([], array_values(array_intersect(self::SIBLING_NAMESPACES, array_keys($loader->getPrefixesPsr4()))));
        }

        $declared = array_filter(get_declared_classes(), static function (string $class): bool {

            foreach (self::SIBLING_NAMESPACES as $namespace) {
                if (str_starts_with($class, $namespace)) {
                    return true;
                }
            }

            return false;
        });

        self::assertSame([], array_values($declared));
    }

    /**
     * Every seam is on the default the provider binds, and every route is one
     * the test's application added, from a closure of its own. Nothing but
     * those seven is there, under any path, and none of them comes from the
     * package. Only a route the framework defines in its own source is left
     * aside, such as the `storage/{path}` routes Laravel 12 serves the local
     * disk's files on.
     *
     * @return void
     */
    public function testEverySeamIsOnItsDefaultAndNoRouteIsThePackages(): void
    {
        $this->assertDefaultBindings();

        $framework = dirname((string) (new \ReflectionClass(Application::class))->getFileName(), 2) . DIRECTORY_SEPARATOR;

        $routes = array_values(array_filter(Route::getRoutes()->getRoutes(), static function (RoutingRoute $route) use ($framework): bool {

            $action = $route->getAction('uses');

            return !$action instanceof \Closure || !str_starts_with((string) (new \ReflectionFunction($action))->getFileName(), $framework);
        }));

        $uris = array_map(static fn (RoutingRoute $route): string => $route->uri(), $routes);

        sort($uris);

        self::assertSame([
            'sso/acs/{connection}',
            'sso/callback/{connection}',
            'sso/discover',
            'sso/jwks/{connection}',
            'sso/metadata/{tenant}/{connection}',
            'sso/redeem/{connection}',
            'sso/start/{connection}',
        ], $uris);

        foreach ($routes as $route) {

            $action = $route->getAction('uses');

            self::assertInstanceOf(\Closure::class, $action);
            self::assertSame(dirname(__DIR__, 2) . '/Concerns/FlowRoutes.php', (new \ReflectionFunction($action))->getFileName());
        }
    }

    /**
     * A configured SAML start redirects to the provider's single sign-on URL,
     * with the request and the relay state its binding carries, and stores one
     * request whose challenge is the verifier the package generated.
     *
     * @return void
     */
    public function testAConfiguredSamlStartProducesItsRedirect(): void
    {
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-start');
        $start      = $this->startedFlow($connection);
        $query      = self::queryOf($start);
        $request    = AuthorizationRequest::query()->sole();

        $this->assertDefaultBindings();

        self::assertSame('redirect', $start['navigation']['type']);
        self::assertStringStartsWith('https://idp-start.example.test/saml/sso?', $start['navigation']['url']);
        self::assertIsString($query['SAMLRequest'] ?? null);
        self::assertIsString($query['RelayState'] ?? null);
        self::assertSame($start['reference'], $request->reference);
        self::assertSame(self::samlRequestIdOf($start), $request->saml_request_id);
        self::assertSame(self::challengeOf($start['verifier']), $request->handoff_challenge);
        self::assertSame($connection->id, $request->connection_id);
        $this->assertEventSequence([AuthorizationRequestStarted::class]);
    }

    /**
     * A configured OIDC start redirects to the provider's authorisation
     * endpoint with the authorisation code request, and fetches nothing, so it
     * runs on the default fetcher.
     *
     * @return void
     */
    public function testAConfiguredOidcStartProducesItsRedirect(): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-start');
        $start      = $this->startedFlow($connection);
        $query      = self::queryOf($start);
        $request    = AuthorizationRequest::query()->sole();

        $this->assertDefaultBindings();

        self::assertSame('redirect', $start['navigation']['type']);
        self::assertStringStartsWith($this->flowProvider($connection)->endpoint('authorization') . '?', $start['navigation']['url']);
        self::assertSame('code', $query['response_type']);
        self::assertSame('client-op-start', $query['client_id']);
        self::assertSame("https://sp.example.test/auth/sso/connections/{$connection->id}/callback", $query['redirect_uri']);
        self::assertSame('S256', $query['code_challenge_method']);
        self::assertIsString($query['state']);
        self::assertIsString($query['nonce']);
        self::assertSame(hash('sha256', $query['state']), $request->state_digest);
        self::assertSame(hash('sha256', $query['nonce']), $request->nonce_digest);
        self::assertSame(self::challengeOf($start['verifier']), $request->handoff_challenge);
        $this->flowFetcher->assertNothingFetched();
        $this->assertEventSequence([AuthorizationRequestStarted::class]);
    }

    /**
     * Rows of `[the protocol]`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideProtocols(): iterable
    {
        yield 'SAML' => [self::SAML];
        yield 'OpenID Connect' => [self::OIDC];
    }

    /**
     * A completion through the default linker offers `ResultUnlinked`
     * synchronously, with no transaction open and no code, then ends
     * `unlinked`: a redirect with the failure code and the reference, and no
     * code on it.
     *
     * @param  string  $protocol
     * @return void
     */
    #[DataProvider('provideProtocols')]
    public function testACompletionThroughNoLinksEndsUnlinked(string $protocol): void
    {
        $connection = $this->connectionOver($protocol, 'unlinked');

        /** @var \ArrayObject<int, array{0: int, 1: int, 2: list<string>}> $offered */
        $offered = new \ArrayObject;

        Event::listen(ResultUnlinked::class, function () use ($offered): void {
            $offered->append([
                DB::connection(StorageConnection::name())->transactionLevel(),
                HandoffCode::query()->count(),
                array_map(static fn (SsoEvent $event): string => $event::class, $this->recordedEvents()),
            ]);
        });

        $start    = $this->startedFlow($connection);
        $response = $this->completeFlow($connection, $start);

        $this->assertOutsideWorldOnly($protocol);

        self::assertSame([[0, 0, [AuthorizationRequestStarted::class, ResultVerified::class]]], $offered->getArrayCopy());
        $this->assertFailedFlow($response, FailureReason::UNLINKED);
        self::assertSame($protocol === self::SAML ? CompletionResponse::SEE_OTHER : CompletionResponse::FOUND, $response->baseResponse->getStatusCode());
        self::assertStringStartsWith(self::FLOW_REDIRECT_URI . '#', (string) $response->baseResponse->headers->get('Location'));
        self::assertSame(['error' => 'unlinked', 'reference' => $start['reference']], self::flowRedirect($response));
        self::assertSame(0, HandoffCode::query()->count());
        self::assertSame(0, Link::query()->count());

        $request = AuthorizationRequest::query()->sole();

        self::assertNotNull($request->consumed_at);
        self::assertNotNull($request->verified_at);
        self::assertNotNull($request->completed_at);

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, ResultUnlinked::class, FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure($protocol === self::SAML ? Flow::ASSERTION : Flow::CALLBACK, FailureReason::UNLINKED);

        self::assertSame($start['reference'], $failure->context->requestReference);
        self::assertSame($connection->id, $failure->context->connectionId);
        self::assertNull($failure->context->identityId);
    }

    /**
     * With unlinked handoffs on, the default store issues a code, holding only
     * its digest, and the default redemption redeems it, with no identity; the
     * code is then spent, and the connection has completed no sign-in. The
     * redemption signs nobody in, sets no cookie and issues no token: what the
     * application makes of the result is its own (FEATURES "Useful alone").
     *
     * @param  string  $protocol
     * @return void
     */
    #[DataProvider('provideProtocols')]
    public function testAnUnlinkedHandoffIsIssuedAndRedeemedThroughTheDefaultStore(string $protocol): void
    {
        config()->set('sso.applications.' . self::FLOW_APPLICATION . '.unlinked_handoffs', true);

        $connection = $this->connectionOver($protocol, 'handoff');
        $start      = $this->startedFlow($connection);
        $code       = $this->completedCode($this->completeFlow($connection, $start));
        $stored     = HandoffCode::query()->sole();

        self::assertSame(hash('sha256', $code), $stored->code_digest);
        self::assertStringNotContainsString($code, (string) json_encode($stored->getAttributes()));
        self::assertNull($stored->redeemed_at);
        self::assertNull($stored->linked_identity_id);

        $answer = $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->assertOk();

        $this->assertOutsideWorldOnly($protocol);

        self::assertInstanceOf(DatabaseHandoffStore::class, $this->app?->make(HandoffIssuer::class));
        self::assertSame('redeemed', $answer->json('status'));
        self::assertSame(self::TENANT, $answer->json('tenant'));
        self::assertSame($connection->id, $answer->json('connection'));
        self::assertSame($start['reference'], $answer->json('reference'));
        self::assertNull($answer->json('linked'));
        self::assertNull($answer->json('link_id'));
        self::assertNotNull(HandoffCode::query()->sole()->redeemed_at);
        self::assertFalse(Connection::query()->whereKey($connection->id)->sole()->has_completed_sign_in);
        self::assertSame([], $answer->headers->getCookies());
        self::assertNull(Auth::guard()->user());

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, ResultUnlinked::class, HandoffIssued::class, HandoffRedeemed::class]);

        $replay = $this->flowRedeem($connection, 'sign_in', $code, $start['verifier']);

        $replay->assertStatus(422);

        self::assertSame(FailureReason::REPLAYED->value, $replay->json('reason'));
    }

    /**
     * The default store records a key once on its real table, keeping only a
     * digest, refuses it while it holds, and records it again once it expired.
     *
     * @return void
     */
    public function testTheDefaultSingleUseStoreRecordsAndRefusesAKey(): void
    {
        $store = $this->app?->make(SingleUseStore::class);
        $now   = CarbonImmutable::parse(self::FLOW_NOW);

        self::assertInstanceOf(DatabaseSingleUseStore::class, $store);
        self::assertSame(SingleUseOutcome::RECORDED, $store->record('standalone', 'a-key', $now->addMinute()));
        self::assertSame(SingleUseOutcome::SEEN, $store->record('standalone', 'a-key', $now->addMinute()));
        self::assertSame(SingleUseOutcome::RECORDED, $store->record('standalone', 'another-key', $now->addMinute()));

        $row = SingleUseKey::query()->where('namespace', 'standalone')->orderBy('id')->first();

        self::assertNotNull($row);
        self::assertSame(2, SingleUseKey::query()->where('namespace', 'standalone')->count());
        self::assertStringNotContainsString('a-key', (string) json_encode($row->getAttributes()));

        Carbon::setTestNow($now->addMinute());

        self::assertSame(SingleUseOutcome::RECORDED, $store->record('standalone', 'a-key', $now->addMinutes(2)));
        self::assertSame(2, SingleUseKey::query()->where('namespace', 'standalone')->count());
    }

    /**
     * A flow's response carrying an assertion already recorded is refused on
     * the real table, though it answers a request of its own.
     *
     * @return void
     */
    public function testTheDefaultSingleUseStoreRefusesAReplayedAssertion(): void
    {
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-replay');
        $sameId     = static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with(['assertion_id' => '_assertion-replayed']);

        $this->assertFailedFlow($this->completeFlow($connection, $this->startedFlow($connection), $sameId), FailureReason::UNLINKED);

        self::assertSame(1, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());

        $this->assertFailedFlow($this->completeFlow($connection, $this->startedFlow($connection), $sameId), FailureReason::REPLAYED);

        self::assertSame(1, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());
        self::assertSame(2, SingleUseKey::query()->where('namespace', 'authorization_request')->count());
        $this->assertDefaultBindings();
    }

    /**
     * The default limiter counts in the database, with a cache that fails on
     * every call: the attempt past the limit is `429` with its wait, its
     * counter gives back no IP address, and the cache was never touched.
     *
     * @return void
     */
    public function testTheDefaultAttemptLimiterLimitsWithoutACache(): void
    {
        $cache = $this->breakTheCache();

        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 2, 'decay_seconds' => 60]);

        $connection = $this->flowSamlConnection(self::TENANT, 'idp-limit');

        $this->flowStart($connection)->assertOk();
        $this->flowStart($connection)->assertOk();

        $refused = $this->flowStart($connection);

        $refused->assertStatus(429);

        self::assertSame(FailureReason::RATE_LIMITED->value, $refused->json('error'));
        self::assertGreaterThanOrEqual(1, $refused->json('retry_after'));
        self::assertLessThanOrEqual(60, $refused->json('retry_after'));
        self::assertSame(2, AuthorizationRequest::query()->count());

        $counter = RateLimit::query()->sole();

        self::assertSame(2, $counter->hits);
        self::assertStringNotContainsString('203.0.113.7', (string) json_encode($counter->getAttributes()));
        self::assertSame(0, $cache->calls);
        $this->assertDefaultBindings();
        $this->assertEventSequence([AuthorizationRequestStarted::class, AuthorizationRequestStarted::class, FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::RATE_LIMITED);
    }

    /**
     * The default revocation deliberately does nothing, and no change waits on
     * it: disabling a connection and changing enforcement each succeed and
     * report their event. `Freshness` is replaced, since its default lets no
     * caller make either change, and every other seam stays on its default.
     *
     * @return void
     */
    public function testTheDefaultRevocationDoesNothingAndChangesSucceed(): void
    {
        config()->set('sso.features.enforcement', true);

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $disabling  = $this->flowSamlConnection(self::TENANT, 'idp-disabling');
        $satisfying = $this->flowSamlConnection(self::TENANT, 'idp-satisfying');

        $satisfying->forceFill(['has_completed_sign_in' => true])->save();

        self::assertInstanceOf(NoSessionRevocation::class, $this->app?->make(SessionRevocation::class));

        $changed  = app(EnforcementService::class)->update(self::TENANT, true, [$satisfying->id]);
        $disabled = app(ConnectionLifecycle::class)->disable(self::TENANT, $disabling->id);

        $this->assertOnlyRebound(Freshness::class);

        self::assertTrue($changed->isChanged());
        self::assertTrue(TenantEnforcement::query()->sole()->enabled);
        self::assertSame(ConnectionStatus::DISABLED, $disabled->status);
        self::assertFalse(Connection::query()->whereKey($disabling->id)->sole()->enabled);
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        $this->assertEventSequence([EnforcementChanged::class, ConnectionDisabled::class]);
    }

    /**
     * The default enforcement reads the database and is off until a tenant turns
     * it on: with the feature on and no rule, a sign-in goes through; with a
     * rule stored, a connection outside it is refused and one inside it goes
     * through, carrying the rule's version.
     *
     * @return void
     */
    public function testTheDefaultEnforcementIsOffUntilATenantTurnsItOn(): void
    {
        config()->set('sso.features.enforcement', true);
        config()->set('sso.applications.' . self::FLOW_APPLICATION . '.unlinked_handoffs', true);

        $outside    = $this->flowSamlConnection(self::TENANT, 'idp-outside');
        $satisfying = $this->flowSamlConnection(self::TENANT, 'idp-inside');
        $default    = $this->app?->make(Enforcement::class);

        self::assertInstanceOf(DatabaseEnforcement::class, $default);

        $before = $default->policy(self::TENANT, self::FLOW_APPLICATION);

        self::assertFalse($before->isRequired());
        self::assertNull($before->version);
        self::assertSame(0, TenantEnforcement::query()->count());

        $free = $this->startedFlow($outside);
        $code = $this->completedCode($this->completeFlow($outside, $free));

        self::assertNull($this->flowRedeem($outside, 'sign_in', $code, $free['verifier'])->assertOk()->json('enforcement_version'));

        $version = $this->turnEnforcementOn($satisfying);
        $after   = $default->policy(self::TENANT, self::FLOW_APPLICATION);

        self::assertTrue($after->isRequired());
        self::assertSame([$satisfying->id], $after->connectionIds);
        self::assertSame($version, $after->version);

        $this->assertFailedFlow($this->completeFlow($outside, $this->startedFlow($outside)), FailureReason::ENFORCEMENT_UNSATISFIED);

        $held = $this->startedFlow($satisfying);
        $kept = $this->completedCode($this->completeFlow($satisfying, $held));

        self::assertSame($version, $this->flowRedeem($satisfying, 'sign_in', $kept, $held['verifier'])->assertOk()->json('enforcement_version'));
        $this->assertDefaultBindings();
    }

    /**
     * With the feature on, discovery routes an email by the domain verified for
     * a connection, and a domain routed nowhere leads to the application's
     * fallback in the same shape, with no request stored for it.
     *
     * @return void
     */
    public function testDiscoveryRoutesByAVerifiedDomain(): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-discovery');

        $this->flowVerifiedDomain($connection, 'discovery.example.com');

        $match = $this->sendFlowRequest('POST', '/sso/discover', ['email' => 'person@discovery.example.com'])->assertOk();
        $miss  = $this->sendFlowRequest('POST', '/sso/discover', ['email' => 'person@nowhere.example.com'])->assertOk();

        $this->assertDefaultBindings();

        $url = $match->json('navigation.url');

        self::assertIsString($url);
        self::assertStringStartsWith($this->flowProvider($connection)->endpoint('authorization') . '?', $url);
        self::assertSame(self::FLOW_FALLBACK_URL, $miss->json('navigation.url'));
        self::assertEqualsCanonicalizing(['reference', 'navigation', 'verifier'], array_keys((array) $match->json()));
        self::assertEqualsCanonicalizing(['reference', 'navigation', 'verifier'], array_keys((array) $miss->json()));

        $request = AuthorizationRequest::query()->sole();

        self::assertSame($match->json('reference'), $request->reference);
        self::assertSame($connection->id, $request->connection_id);
        self::assertSame(self::DISCOVERING_APPLICATION, $request->application);
    }

    /**
     * With the feature off, the same start is refused and nothing is routed.
     *
     * @return void
     */
    public function testDiscoveryRoutesNothingWithTheFeatureOff(): void
    {
        config()->set('sso.features.discovery', false);

        $connection = $this->flowOidcConnection(self::TENANT, 'op-discovery-off');

        $this->flowVerifiedDomain($connection, 'discovery.example.com');

        $refused = $this->sendFlowRequest('POST', '/sso/discover', ['email' => 'person@discovery.example.com']);

        $refused->assertStatus(422);

        self::assertSame(FailureReason::FEATURE_DISABLED->value, $refused->json('error'));
        self::assertSame(0, AuthorizationRequest::query()->count());
    }

    /**
     * Service provider metadata of each protocol and a connection's public keys
     * are served. The key is made under a fresh caller, the only way a key
     * comes to be, and the default is then put back, since serving it asks
     * nothing of a caller.
     *
     * @return void
     */
    public function testServiceProviderMetadataAndJwksAreServed(): void
    {
        $saml = $this->flowSamlConnection(self::TENANT, 'idp-metadata');
        $oidc = $this->flowOidcConnection(self::TENANT, 'op-metadata', settings: ['client_authentication' => 'private_key_jwt']);

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        app(KeyService::class)->addNext(self::TENANT, $oidc->id, KeyUse::CLIENT_ASSERTION, KeyType::EC);

        $this->app?->instance(Freshness::class, new RefusingFreshness);

        $samlMetadata = $this->sendFlowRequest('GET', '/sso/metadata/' . self::TENANT . "/{$saml->id}")->assertOk();
        $oidcMetadata = $this->sendFlowRequest('GET', '/sso/metadata/' . self::TENANT . "/{$oidc->id}")->assertOk();
        $jwks         = $this->sendFlowRequest('GET', "/sso/jwks/{$oidc->id}")->assertOk();

        $this->assertDefaultBindings();

        self::assertStringStartsWith('<md:EntityDescriptor', (string) $samlMetadata->baseResponse->getContent());
        self::assertStringContainsString("https://sp.example.test/auth/sso/connections/{$saml->id}/assertions", (string) $samlMetadata->baseResponse->getContent());
        self::assertSame(["https://sp.example.test/auth/sso/connections/{$oidc->id}/callback"], $oidcMetadata->json('redirect_uris'));
        self::assertCount(1, (array) $jwks->json('keys'));
        self::assertArrayNotHasKey('d', (array) $jwks->json('keys.0'));
    }

    /**
     * `sso:prune` deletes one row of each kind on the defaults, says so on one
     * line, and finds nothing the second time.
     *
     * @return void
     */
    public function testPruneWorksOnTheDefaults(): void
    {
        $connection = $this->makeConnection();
        $expired    = CarbonImmutable::parse(self::FLOW_NOW)->subDays(2);

        foreach (PruneKind::cases() as $kind) {
            $this->prunableRow($kind, $connection, $expired);
        }

        [$code, $output] = $this->artisanLines('sso:prune');

        self::assertSame(0, $code);
        self::assertSame(['Pruned (complete): authorization_requests 1, handoff_codes 1, single_use_keys 1, reservations 1, pending_claims 1, rate_limits 1'], $output);

        [$code, $output] = $this->artisanLines('sso:prune');

        self::assertSame(0, $code);
        self::assertSame(['Pruned (complete): authorization_requests 0, handoff_codes 0, single_use_keys 0, reservations 0, pending_claims 0, rate_limits 0'], $output);
        $this->assertDefaultBindings();
    }

    /**
     * `sso:keys:expiring` lists a certificate that ends tomorrow and warns of
     * it once on the defaults; a second run lists it and sends nothing.
     *
     * @return void
     */
    public function testExpiringKeysWorksOnTheDefaults(): void
    {
        $connection = $this->makeConnection(['protocol' => 'saml2']);
        $key        = $this->certificateEndingTomorrow($connection);
        $line       = sprintf('[expiring] key %s (connection %s, idp_signing) ends 2026-11-02T09:30:00Z, threshold 1: ', $key->id, $connection->id);

        [$code, $output] = $this->artisanLines('sso:keys:expiring');

        self::assertSame(0, $code);
        self::assertSame([$line . 'notified', 'Keys listed: 1, expired 0; warnings: notified 1, already_notified 0, not_due 0, claimed 0, failed 0'], $output);

        [$code, $output] = $this->artisanLines('sso:keys:expiring');

        self::assertSame(0, $code);
        self::assertSame([$line . 'already_notified', 'Keys listed: 1, expired 0; warnings: notified 0, already_notified 1, not_due 0, claimed 0, failed 0'], $output);

        $this->assertEventSequence([KeyNearingExpiry::class]);

        $warning = $this->recordedEvents()[0];

        self::assertInstanceOf(KeyNearingExpiry::class, $warning);
        self::assertSame($key->id, $warning->keyId);
        self::assertSame(1, $warning->thresholdDays);
        $this->assertDefaultBindings();
    }

    /**
     * A usable connection over the protocol at a host of its own. An OIDC
     * completion reaches its provider, the one part of the outside world that
     * needs a seam replaced, so its fake fetcher is bound first.
     *
     * @param  string  $protocol
     * @param  string  $host
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connectionOver(string $protocol, string $host): Connection
    {
        if ($protocol === self::SAML) {
            return $this->flowSamlConnection(self::TENANT, "idp-{$host}");
        }

        $this->app?->instance(Fetcher::class, $this->flowFetcher);

        return $this->flowOidcConnection(self::TENANT, "op-{$host}");
    }

    /**
     * Assert nothing but the outside world the protocol needs has been
     * replaced.
     *
     * @param  string  $protocol
     * @return void
     */
    private function assertOutsideWorldOnly(string $protocol): void
    {
        if ($protocol === self::SAML) {
            $this->assertDefaultBindings();

            return;
        }

        $this->assertOnlyRebound(Fetcher::class);
    }

    /**
     * Assert the seams named are off their defaults, and every other is on its
     * own.
     *
     * @param  class-string  ...$rebound
     * @return void
     */
    private function assertOnlyRebound(string ...$rebound): void
    {
        foreach (self::DEFAULT_BINDINGS as $seam => $default) {

            if (in_array($seam, $rebound, true)) {
                self::assertNotInstanceOf($default, $this->app?->make($seam), "{$seam} was to be replaced.");

                continue;
            }

            self::assertInstanceOf($default, $this->app?->make($seam), "{$seam} is not bound to its default.");
        }
    }

    /**
     * Store the rule a tenant's own change would have stored, on the row the
     * last flow's locks left unconfigured, so that no seam need be replaced to
     * change it; answer its version.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $satisfying
     * @return string
     */
    private function turnEnforcementOn(Connection $satisfying): string
    {
        $version = strtolower((string) Str::ulid());

        TenantEnforcement::query()->sole()->forceFill([
            'enabled'        => true,
            'connection_ids' => [$satisfying->id],
            'version'        => $version,
            'changed_at'     => CarbonImmutable::parse(self::FLOW_NOW),
        ])->save();

        return $version;
    }

    /**
     * A certificate the connection trusts, whose validity ends a day from now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private function certificateEndingTomorrow(Connection $connection): ConnectionKey
    {
        $masked = MaskedKey::fromCertificate(self::flowIdp('idp-expiring')->certificate());
        $key    = new ConnectionKey;

        $key->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $masked->certificate,
            'public_key'    => $masked->publicKey,
            'fingerprint'   => $masked->fingerprint,
            'not_after'     => CarbonImmutable::parse(self::FLOW_NOW)->addDay(),
        ])->save();

        return $key;
    }

    /**
     * The S256 challenge of the verifier.
     *
     * @param  string  $verifier
     * @return string
     */
    private static function challengeOf(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    /**
     * Run the command, and answer its exit code and the lines it printed,
     * without blank ones.
     *
     * @param  string  $command
     * @return array{0: int, 1: list<string>}
     */
    private function artisanLines(string $command): array
    {
        $code   = Artisan::call($command);
        $output = array_values(array_filter(explode("\n", trim(Artisan::output())), static fn (string $line): bool => $line !== ''));

        return [$code, $output];
    }
}
