<?php

declare(strict_types = 1);

namespace Tests\Integration\Standalone;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Evidence\InsufficientEvidence;
use SineMacula\Laravel\Sso\Exceptions\InvalidConfigurationException;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\NoReauthenticationSessions;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\RefusingFreshness;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\LinkingCheck;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;
use SineMacula\Laravel\Sso\Linking\NoEmailMatches;
use SineMacula\Laravel\Sso\Linking\NoTenantMembership;
use SineMacula\Laravel\Sso\Linking\RefusingLinkConfirmation;
use SineMacula\Laravel\Sso\Linking\RefusingLinkEligibility;
use SineMacula\Laravel\Sso\Linking\RefusingPrincipalScope;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Links\LinkStorageBinding;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Tests\Concerns\FlowRoutes;
use Tests\Concerns\RaceFlows;
use Tests\Concerns\RecordsEventSequences;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\Fixtures\Linking\ScriptedEmailMatcher;
use Tests\Fixtures\Linking\ScriptedPrincipalScope;
use Tests\Fixtures\Linking\ScriptedTenantMembership;
use Tests\StandaloneTestCase;

/**
 * What the defaults refuse (FEATURES "Sensible behaviour alone"), each asserted
 * with its exact reason in the flow that consults it, over the real drivers: a
 * contract that holds nothing a package could know answers so as to fail
 * closed, rather than let an application go on as though it had answered.
 *
 * A default deep inside a flow is only reached once what comes before it has
 * answered, so a test replaces those seams, the fake fetcher among them, names
 * them, and shows every other seam, the one it proves above all, is on its
 * default. What a default deliberately allows is `DefaultBindingsFlowsTest`'s.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefusingFreshness::class)]
#[CoversClass(RefusingLinkEligibility::class)]
#[CoversClass(RefusingLinkConfirmation::class)]
#[CoversClass(RefusingPrincipalScope::class)]
#[CoversClass(NoEmailMatches::class)]
#[CoversClass(NoTenantMembership::class)]
#[CoversClass(InsufficientEvidence::class)]
#[CoversClass(NoReauthenticationSessions::class)]
#[CoversClass(LinkStorageBinding::class)]
#[CoversClass(LinkingCheck::class)]
final class DefaultBindingsRefusalsTest extends StandaloneTestCase
{
    use FlowRoutes, RaceFlows, RecordsEventSequences;

    /** @var string The tenant of every connection. */
    private const string TENANT = 'tenant-1';

    /** @var string The email an identity provider asserts, of the claimed domain. */
    private const string EMAIL = 'person@example.com';

    /** @var string The domain the email belongs to. */
    private const string DOMAIN = 'example.com';

    /** @var string The start URL an IdP-initiated response is sent to. */
    private const string IDP_START_URL = 'https://app.example.com/sso/start';

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The identity a flow concerns. */
    private IdentityReference $person;

    /**
     * Stop Laravel's clock, which the default clock follows, configure the
     * protocols, the endpoints, the features each refusal needs and an
     * application, and create the tables and the routes an application adds.
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
        $this->person       = new IdentityReference('App\Models\User', 'person-1');

        config()->set('app.debug', false);
        config()->set('sso.features.saml2', true);
        config()->set('sso.features.oidc', true);
        config()->set('sso.features.enforcement', true);
        config()->set('sso.features.idp_initiated', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', [self::FLOW_APPLICATION => ['redirect_uri' => self::FLOW_REDIRECT_URI, 'external_sign_in' => true]]);

        $this->assertStandalone();
        $this->usePackageTables();
        $this->registerFlowRoutes();
    }

    /**
     * Every operation has a change that makes it here.
     *
     * @return void
     */
    public function testEveryOperationIsMade(): void
    {
        $names = array_map(static fn (FreshnessOperation $operation): string => $operation->value, FreshnessOperation::cases());

        self::assertSame($names, array_keys($this->operations()));
    }

    /**
     * The twelve operations of SSO-2.12, none left out.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation}>
     */
    public static function provideOperations(): iterable
    {
        foreach (FreshnessOperation::cases() as $operation) {
            yield $operation->value => [$operation];
        }
    }

    /**
     * Under the default, each operation's change refuses `freshness_required`:
     * no row changes, and nothing is reported but the one failure a start
     * always reports. A start counts its attempt first, which is no part of it.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @return void
     */
    #[DataProvider('provideOperations')]
    public function testEveryOperationRefuses(FreshnessOperation $operation): void
    {
        $reason = $this->operations()[$operation->value]();

        $this->assertDefaultBindings();

        self::assertInstanceOf(RefusingFreshness::class, $this->app?->make(Freshness::class));
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $reason);
    }

    /**
     * The start of a `reauthenticate` asks the default sessions, which hold
     * none, and is `session_ineligible`, with no request stored.
     *
     * @return void
     */
    public function testNoReauthenticationSessionsRefusesAStart(): void
    {
        $this->startRecordingEvents();

        $connection = $this->flowSamlConnection(self::TENANT, 'idp-reauthenticate');
        $refused    = $this->flowStart($connection, 'reauthenticate', $this->person, 'session-1');

        $this->assertDefaultBindings();

        $refused->assertStatus(422);

        self::assertSame(['error' => FailureReason::SESSION_INELIGIBLE->value], $refused->json());
        self::assertSame(0, AuthorizationRequest::query()->count());
        $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::SESSION_INELIGIBLE);
    }

    /**
     * A `link` through the default eligibility is `link_ineligible` at
     * completion, with no code and no link: no identity may link until the
     * application says so.
     *
     * @return void
     */
    public function testRefusingLinkEligibilityRefusesALink(): void
    {
        $connection = $this->openIdConnection('op-eligibility');

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(Linker::class, app(LinkStore::class));

        $response = $this->completeFlow($connection, $this->startedFlow($connection, 'link', $this->person));

        $this->assertOnlyRebound(Fetcher::class, Freshness::class, Linker::class);
        $this->assertFailedFlow($response, FailureReason::LINK_INELIGIBLE);

        self::assertSame(0, Link::query()->count());
        self::assertSame(0, HandoffCode::query()->count());
    }

    /**
     * A `link` of an identity that holds a link by a verified domain, in any
     * connection, needs a confirmation the default never gives, and its
     * redemption is `independent_authentication_required`; no link is made.
     *
     * @return void
     */
    public function testRefusingLinkConfirmationRefusesALink(): void
    {
        $connection = $this->openIdConnection('op-confirmation');
        $elsewhere  = $this->makeConnection(['enabled' => true]);

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(Linker::class, app(LinkStore::class));
        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);

        $this->holdByVerifiedDomain($elsewhere, new LinkSubject('https://elsewhere.example.test', 'subject-elsewhere'));

        $start = $this->startedFlow($connection, 'link', $this->person);
        $code  = $this->completedCode($this->completeFlow($connection, $start));

        $refused = $this->flowRedeem($connection, 'link', $code, $start['verifier'], $this->person);

        $this->assertOnlyRebound(Fetcher::class, Freshness::class, Linker::class, LinkEligibility::class);

        $refused->assertStatus(422);

        self::assertSame(FailureReason::INDEPENDENT_AUTHENTICATION_REQUIRED->value, $refused->json('reason'));
        self::assertSame(0, Link::query()->where('connection_id', $connection->id)->count());
    }

    /**
     * A link standing on a verified domain asks the default scope, which knows
     * no principals: its `sign_in` is `principal_scope_unknown`, and the link
     * stays as it was, since uncertainty asserts no widening.
     *
     * @return void
     */
    public function testRefusingPrincipalScopeRefusesASignInThroughADomainLink(): void
    {
        $connection = $this->openIdConnection('op-scope');

        $this->app?->instance(Linker::class, app(LinkStore::class));

        $this->holdByVerifiedDomain($connection, new LinkSubject($this->flowProvider($connection)->issuer, FakeOpenIdProvider::SUBJECT));

        $response = $this->completeFlow($connection, $this->startedFlow($connection));

        $this->assertOnlyRebound(Fetcher::class, Linker::class);
        $this->assertFailedFlow($response, FailureReason::PRINCIPAL_SCOPE_UNKNOWN);

        $link = Link::query()->sole();

        self::assertSame(LinkState::ACTIVE, $link->state);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $link->provenance);
        self::assertSame(0, HandoffCode::query()->count());
    }

    /**
     * Linking by a verified domain asks the default scope before it reserves:
     * the person's membership is not even asked about, nothing is reserved, and
     * the sign-in ends `unlinked`.
     *
     * @return void
     */
    public function testRefusingPrincipalScopeReservesNothing(): void
    {
        $connection = $this->linkingConnection('op-scope-reservation');
        $membership = new ScriptedTenantMembership(MembershipStanding::accepted(CarbonImmutable::parse(self::FLOW_NOW)->subDays(2)));

        $membership->failure = new \LogicException('The membership was asked about.');

        $this->app?->instance(LinkEmailMatcher::class, new ScriptedEmailMatcher(LinkEmailMatch::exactlyOne($this->person)));
        $this->app?->instance(TenantMembership::class, $membership);

        $response = $this->completeFlow($connection, $this->startedFlow($connection), self::verifiedEmail());

        $this->assertOnlyRebound(Fetcher::class, Linker::class, LinkEmailMatcher::class, TenantMembership::class);
        $this->assertFailedFlow($response, FailureReason::UNLINKED);

        self::assertSame(0, Link::query()->count());
    }

    /**
     * Linking by a verified domain asks the default matcher, which finds
     * nobody, so nothing is reserved and the sign-in ends `unlinked`.
     *
     * @return void
     */
    public function testNoEmailMatchesReservesNothing(): void
    {
        $connection = $this->linkingConnection('op-matches');
        $response   = $this->completeFlow($connection, $this->startedFlow($connection), self::verifiedEmail());

        $this->assertOnlyRebound(Fetcher::class, Linker::class);
        $this->assertFailedFlow($response, FailureReason::UNLINKED);

        self::assertSame(0, Link::query()->count());
    }

    /**
     * Linking by a verified domain with a sole match, within the tenant, asks
     * the default membership, which holds none: nothing is reserved, and the
     * sign-in ends `unlinked`, once the scope has answered.
     *
     * @return void
     */
    public function testNoTenantMembershipReservesNothing(): void
    {
        $connection = $this->linkingConnection('op-membership');
        $scope      = new ScriptedPrincipalScope;

        $this->app?->instance(LinkEmailMatcher::class, new ScriptedEmailMatcher(LinkEmailMatch::exactlyOne($this->person)));
        $this->app?->instance(PrincipalScope::class, $scope);

        $response = $this->completeFlow($connection, $this->startedFlow($connection), self::verifiedEmail());

        $this->assertOnlyRebound(Fetcher::class, Linker::class, LinkEmailMatcher::class, PrincipalScope::class);
        $this->assertFailedFlow($response, FailureReason::UNLINKED);

        self::assertSame([[$this->person->type, $this->person->id, self::TENANT]], $scope->asked);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * A linked `sign_in` is redeemed, and what the provider asserted counts for
     * nothing under the default evidence.
     *
     * @return void
     */
    public function testInsufficientEvidenceAcceptsNothing(): void
    {
        $connection = $this->openIdConnection('op-evidence');

        $this->app?->instance(Linker::class, app(LinkStore::class));

        $subject = new LinkSubject($this->flowProvider($connection)->issuer, FakeOpenIdProvider::SUBJECT);

        self::assertTrue(app(LinkStore::class)->create($connection, $subject, $this->person, LinkOrigin::LINK_PURPOSE)->isCreated());

        $start = $this->startedFlow($connection);
        $code  = $this->completedCode($this->completeFlow($connection, $start));

        $answer = DB::connection(StorageConnection::name())->transaction(
            static fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, self::FLOW_APPLICATION, $connection->id, $code, $start['verifier']),
        );

        $this->assertOnlyRebound(Fetcher::class, Linker::class);

        self::assertTrue($answer->isAdmitted());
        self::assertTrue($this->person->is($answer->linkedIdentity ?? new IdentityReference('nobody', 'nobody')));
        self::assertNull($answer->evidence);
    }

    /**
     * With linking by a verified domain on over the default linker, `sso:check`
     * fails with the problem under its own subject, naming the linker and the
     * way out; with the store bound, or the feature off, that subject passes.
     *
     * @return void
     */
    public function testTheConfigurationCommandReportsLinkingWithNoStorage(): void
    {
        config()->set('sso.features.domain_linking', true);

        [$code, $output] = $this->configurationCheck();

        $this->assertDefaultBindings();

        self::assertSame(1, $code);
        self::assertContains('[linking] ' . self::noStorageProblem(), $output);

        $this->app?->instance(Linker::class, app(LinkStore::class));

        self::assertContains('[linking] OK', $this->configurationCheck()[1]);

        $this->app?->instance(Linker::class, new NoLinks);

        config()->set('sso.features.domain_linking', false);

        self::assertContains('[linking] OK', $this->configurationCheck()[1]);
    }

    /**
     * The same problem stops an application serving a request as it boots.
     *
     * @return void
     */
    public function testTheBootCheckRefusesLinkingWithNoStorage(): void
    {
        config()->set('sso.features.domain_linking', true);

        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        (new \ReflectionProperty(Application::class, 'isRunningInConsole'))->setValue($app, false);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('[linking] ' . self::noStorageProblem());

        (new SsoServiceProvider($app))->boot();
    }

    /**
     * The same problem stops a worker command as it starts.
     *
     * @return void
     */
    public function testAWorkerCommandRefusesLinkingWithNoStorage(): void
    {
        config()->set('sso.features.domain_linking', true);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('[linking] ' . self::noStorageProblem());

        $this->app?->make(Dispatcher::class)->dispatch(new CommandStarting('queue:work', new ArrayInput([]), new BufferedOutput));
    }

    /**
     * The settings service refuses to turn linking on over the default linker,
     * with nothing written, once a caller is fresh enough to reach it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSettingsServiceRefusesLinkingWithNoStorage(): void
    {
        config()->set('sso.features.domain_linking', true);

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $connection = $this->flowOidcConnection(self::TENANT, 'op-settings');
        $version    = Connection::query()->whereKey($connection->id)->sole()->linking_version;

        $this->startRecordingEvents();

        try {
            app(LinkingPolicyService::class)->change(self::TENANT, $connection->id, ['enabled' => true, 'issuer_class' => 'single_organization', 'acknowledged' => true]);

            self::fail('Linking went on over a linker that would ignore its rows.');
        } catch (\LogicException $exception) {
            self::assertStringStartsWith('Linking by a verified domain needs links its resolver reads', $exception->getMessage());
        }

        $stored = Connection::query()->whereKey($connection->id)->sole();

        $this->assertOnlyRebound(Freshness::class);

        self::assertFalse($stored->linking_enabled);
        self::assertSame($version, $stored->linking_version);
        $this->assertNoEvents();
    }

    /**
     * A `link` completed over the default linker refuses before anything is
     * written: its request stays consumed, since that committed first, and is
     * not finished.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testALinkCompletionRefusesWithNoStorage(): void
    {
        $connection = $this->openIdConnection('op-completion');

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $start = $this->startedFlow($connection, 'link', $this->person);

        $this->startRecordingEvents();

        try {
            $this->callbackFor($connection, $start);

            self::fail('A link went on over a linker that would ignore it.');
        } catch (\LogicException $exception) {
            self::assertStringStartsWith('A [link] flow needs links its resolver reads', $exception->getMessage());
        }

        $this->assertOnlyRebound(Fetcher::class, Freshness::class);

        $request = AuthorizationRequest::query()->sole();

        self::assertNotNull($request->consumed_at);
        self::assertNull($request->completed_at);
        self::assertSame(0, Link::query()->count());
        self::assertSame(0, HandoffCode::query()->count());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        $this->assertNoEvents();
    }

    /**
     * A `link` redeemed over the default linker refuses, leaving the code as it
     * was; once the store is bound again the same code goes through.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkRedemptionRefusesWithNoStorage(): void
    {
        $connection = $this->openIdConnection('op-redemption');
        $store      = app(LinkStore::class);

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
        $this->app?->instance(Linker::class, $store);

        $start = $this->startedFlow($connection, 'link', $this->person);
        $code  = $this->completedCode($this->completeFlow($connection, $start));

        $this->app?->instance(Linker::class, new NoLinks);

        try {
            app(HandoffRedemption::class)->redeem(Purpose::LINK, self::FLOW_APPLICATION, $connection->id, $code, $start['verifier'], $this->person);

            self::fail('A link was redeemed over a linker that would ignore it.');
        } catch (\LogicException $exception) {
            self::assertStringStartsWith('A [link] redemption needs links its resolver reads', $exception->getMessage());
        }

        $this->assertOnlyRebound(Fetcher::class, Freshness::class, LinkEligibility::class);

        self::assertNull(HandoffCode::query()->sole()->redeemed_at);
        self::assertSame(0, Link::query()->count());

        $this->app?->instance(Linker::class, $store);

        self::assertTrue(app(HandoffRedemption::class)->redeem(Purpose::LINK, self::FLOW_APPLICATION, $connection->id, $code, $start['verifier'], $this->person)->isRedeemed());
        self::assertSame($this->person->id, Link::query()->sole()->identity_id);
    }

    /**
     * What makes each operation's change, by the operation's name.
     *
     * @return array<string, \Closure(): ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason>
     */
    private function operations(): array
    {
        return [
            'sso.connection.trust'         => $this->createConnection(...),
            'sso.connection.enable'        => $this->enableConnection(...),
            'sso.connection.disable'       => $this->disableConnection(...),
            'sso.connection.delete'        => $this->deleteConnection(...),
            'sso.connection.idp_initiated' => $this->turnIdpInitiatedOn(...),
            'sso.keys.rotate'              => $this->rotateKey(...),
            'sso.domain.claim'             => $this->claimDomain(...),
            'sso.domain.verify'            => $this->verifyDomain(...),
            'sso.domain.remove'            => $this->removeDomain(...),
            'sso.enforcement.update'       => $this->updateEnforcement(...),
            'sso.link.create'              => $this->startLink(...),
            'sso.link.remove'              => $this->removeLink(...),
        ];
    }

    /**
     * Creating a connection is `sso.connection.trust`.
     *
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function createConnection(): ?FailureReason
    {
        return $this->withNothingWritten(static fn (): ?FailureReason => app(ConnectionService::class)->create(self::TENANT, 'oidc', 'Acme')->reason);
    }

    /**
     * Enabling a connection is `sso.connection.enable`.
     *
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function enableConnection(): ?FailureReason
    {
        $connection = $this->makeConnection();

        return $this->withNothingWritten(static fn (): ?FailureReason => app(ConnectionService::class)->enable(self::TENANT, $connection->id)->reason);
    }

    /**
     * Disabling a connection is `sso.connection.disable`.
     *
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function disableConnection(): ?FailureReason
    {
        $connection = $this->makeConnection(['enabled' => true]);

        return $this->withNothingWritten(static fn (): ?FailureReason => app(ConnectionLifecycle::class)->disable(self::TENANT, $connection->id)->reason);
    }

    /**
     * Deleting a connection is `sso.connection.delete`.
     *
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function deleteConnection(): ?FailureReason
    {
        $connection = $this->makeConnection();

        return $this->withNothingWritten(static fn (): ?FailureReason => app(ConnectionLifecycle::class)->delete(self::TENANT, $connection->id)->reason);
    }

    /**
     * Turning IdP-initiated sign-in on is `sso.connection.idp_initiated`.
     *
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function turnIdpInitiatedOn(): ?FailureReason
    {
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-initiated');
        $changes    = ['settings' => ['idp_initiated' => true, 'idp_initiated_start_url' => self::IDP_START_URL]];

        return $this->withNothingWritten(static fn (): ?FailureReason => app(ConnectionService::class)->update(self::TENANT, $connection->id, $changes)->reason);
    }

    /**
     * Adding a service provider key is `sso.keys.rotate`.
     *
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function rotateKey(): ?FailureReason
    {
        $connection = $this->makeConnection(['protocol' => 'saml2']);

        return $this->withNothingWritten(static fn (): ?FailureReason => app(KeyService::class)->addNext(self::TENANT, $connection->id, KeyUse::SP_SIGNING)->reason);
    }

    /**
     * Claiming a domain is `sso.domain.claim`.
     *
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function claimDomain(): ?FailureReason
    {
        $connection = $this->makeConnection();

        return $this->withNothingWritten(static fn (): ?FailureReason => app(DomainService::class)->claim(self::TENANT, $connection->id, self::DOMAIN)->reason);
    }

    /**
     * Verifying a domain is `sso.domain.verify`, asked before any lookup.
     *
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function verifyDomain(): ?FailureReason
    {
        $connection = $this->makeConnection();

        $this->makeDomain($connection, self::DOMAIN);

        return $this->withNothingWritten(static fn (): ?FailureReason => app(DomainService::class)->verify(self::TENANT, $connection->id, self::DOMAIN)->reason);
    }

    /**
     * Removing a domain is `sso.domain.remove`.
     *
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function removeDomain(): ?FailureReason
    {
        $connection = $this->makeConnection();

        $this->makeDomain($connection, self::DOMAIN);

        return $this->withNothingWritten(static fn (): ?FailureReason => app(DomainService::class)->remove(self::TENANT, $connection->id, self::DOMAIN)->reason);
    }

    /**
     * Turning enforcement on is `sso.enforcement.update`, asked once what it
     * was given would be allowed.
     *
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function updateEnforcement(): ?FailureReason
    {
        $connection = $this->makeConnection(['enabled' => true, 'has_completed_sign_in' => true]);

        return $this->withNothingWritten(static fn (): ?FailureReason => app(EnforcementService::class)->update(self::TENANT, true, [$connection->id])->reason);
    }

    /**
     * Starting a `link` is `sso.link.create`, and the one of these a flow
     * makes, so it reports its failure.
     *
     * @return \SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function startLink(): FailureReason
    {
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-link');
        $before     = self::rowsBeyondCounters();

        $this->startRecordingEvents();

        $refused = $this->flowStart($connection, 'link', $this->person);

        $refused->assertStatus(422);

        self::assertSame($before, self::rowsBeyondCounters());

        $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::FRESHNESS_REQUIRED);

        $error = $refused->json('error');

        self::assertIsString($error);

        return FailureReason::from($error);
    }

    /**
     * Removing a link is `sso.link.remove`.
     *
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function removeLink(): ?FailureReason
    {
        $connection = $this->makeConnection();
        $link       = $this->makeLink($connection, 'subject-1', ['identity_type' => $this->person->type, 'identity_id' => $this->person->id]);
        $person     = $this->person;

        return $this->withNothingWritten(static fn (): ?FailureReason => app(LinkService::class)->remove($person, $link->id)->reason);
    }

    /**
     * What the helper refused with, once it has shown it wrote and reported
     * nothing.
     *
     * @param  \Closure(): ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $helper
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function withNothingWritten(\Closure $helper): ?FailureReason
    {
        $before = self::rowsBeyondCounters();

        $this->startRecordingEvents();

        $reason = $helper();

        self::assertSame($before, self::rowsBeyondCounters());

        $this->assertNoEvents();

        return $reason;
    }

    /**
     * Every row of the package's tables, but the attempt counters.
     *
     * @return array<string, list<string>>
     */
    private static function rowsBeyondCounters(): array
    {
        return array_diff_key(self::storedRows(), [StorageConnection::table('rate_limits.table') => true]);
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
     * A usable OIDC connection at the host, its provider answering on the fake
     * fetcher, which is bound first, since a driver keeps what it was built
     * with.
     *
     * @param  string  $host
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function openIdConnection(string $host): Connection
    {
        $this->app?->instance(Fetcher::class, $this->flowFetcher);

        return $this->flowOidcConnection(self::TENANT, $host);
    }

    /**
     * An OIDC connection with linking by a verified domain on, classified one
     * organisation's and acknowledged, holding the verified claim of the
     * email's domain, last checked now, with the feature on and the store
     * bound.
     *
     * @param  string  $host
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function linkingConnection(string $host): Connection
    {
        config()->set('sso.features.domain_linking', true);

        $this->app?->instance(Linker::class, app(LinkStore::class));

        $connection = $this->openIdConnection($host);
        $now        = CarbonImmutable::parse(self::FLOW_NOW);

        $connection->forceFill([
            'linking_enabled'         => true,
            'linking_issuer_class'    => 'single_organization',
            'linking_acknowledged_at' => $now->subDay(),
        ])->save();

        $this->makeDomain($connection, self::DOMAIN, [
            'state'                    => DomainState::VERIFIED,
            'verified_domain'          => self::DOMAIN,
            'verified_at'              => $now->subDay(),
            'verification_generation'  => 1,
            'last_successful_check_at' => $now,
        ]);

        return $connection;
    }

    /**
     * Have the person hold a link by a verified domain, through the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @return void
     */
    private function holdByVerifiedDomain(Connection $connection, LinkSubject $subject): void
    {
        self::assertTrue(app(LinkStore::class)->create($connection, $subject, $this->person, LinkOrigin::VERIFIED_DOMAIN)->isCreated());
    }

    /**
     * What has an ID token assert the email, verified.
     *
     * @return \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken
     */
    private static function verifiedEmail(): \Closure
    {
        return static fn (FakeIdToken $token): FakeIdToken => $token->with('email', self::EMAIL)->with('email_verified', true);
    }

    /**
     * Answer the flow at the connection's callback, through the service, so
     * what it throws reaches the test.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  array{navigation: array{url: string}}  $start
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function callbackFor(Connection $connection, array $start): CompletionResult
    {
        return app(CompletionService::class)->callback($connection->id, new CompletionRequest('GET', $this->flowGrant($connection, $start)->query(), []));
    }

    /**
     * What is wrong with linking by a verified domain over the default linker.
     *
     * @return string
     */
    private static function noStorageProblem(): string
    {
        return sprintf(
            'The `domain_linking` feature needs links its resolver reads, but the [%s] bound as [%s] does not implement [%s]: bind [%s], or a wrapper that delegates to it.',
            NoLinks::class,
            Linker::class,
            LinkStorage::class,
            LinkStore::class,
        );
    }

    /**
     * Run `sso:check`, and answer its exit code and the lines it printed,
     * trimmed, without blank ones.
     *
     * @return array{0: int, 1: list<string>}
     */
    private function configurationCheck(): array
    {
        $code   = Artisan::call('sso:check');
        $output = array_values(array_filter(array_map(trim(...), explode("\n", Artisan::output())), static fn (string $line): bool => $line !== ''));

        return [$code, $output];
    }
}
