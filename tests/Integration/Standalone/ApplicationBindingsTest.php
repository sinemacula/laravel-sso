<?php

declare(strict_types = 1);

namespace Tests\Integration\Standalone;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Completion\Stages\IssueHandoff;
use SineMacula\Laravel\Sso\Completion\Stages\RecordReplay;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\ProviderSessionDeadline;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\ConnectionDisabled;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\LinkActivated;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestConsumption;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\Redemption\LinkBranch;
use SineMacula\Laravel\Sso\Handoffs\Redemption\SignInBranch;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStorageBinding;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Models\RateLimit;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FrozenClock;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Concerns\FlowRoutes;
use Tests\Concerns\RecordsEventSequences;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\Fixtures\Linking\ScriptedEmailMatcher;
use Tests\Fixtures\Linking\ScriptedPrincipalScope;
use Tests\Fixtures\Linking\ScriptedTenantMembership;
use Tests\Fixtures\Standalone\ApplicationAttemptLimiter;
use Tests\Fixtures\Standalone\ApplicationFreshness;
use Tests\Fixtures\Standalone\ApplicationHandoffIssuer;
use Tests\Fixtures\Standalone\ApplicationLinker;
use Tests\Fixtures\Standalone\ApplicationRevocation;
use Tests\Fixtures\Standalone\ApplicationSingleUseStore;
use Tests\StandaloneTestCase;

/**
 * Integration tests replacing each application seam on its own.
 *
 * Each test also binds the seams its flow needs to reach the one it proves, and
 * asserts every other is on its default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkStorageBinding::class)]
#[CoversClass(LinkBranch::class)]
#[CoversClass(SignInBranch::class)]
#[CoversClass(IssueHandoff::class)]
#[CoversClass(LinkReservations::class)]
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(ConnectionLifecycle::class)]
#[CoversClass(EnforcementService::class)]
#[CoversClass(FreshnessGate::class)]
#[CoversClass(RecordReplay::class)]
#[CoversClass(RequestConsumption::class)]
#[CoversClass(DomainRechecker::class)]
#[CoversClass(HandoffRedemption::class)]
final class ApplicationBindingsTest extends StandaloneTestCase
{
    use FlowRoutes, RecordsEventSequences;

    /** @var string The tenant of every connection. */
    private const string TENANT = 'tenant-1';

    /** @var string The email an identity provider asserts, of the claimed domain. */
    private const string EMAIL = 'person@example.com';

    /** @var string The link a resolver-only linker answers: the full width of a link's id. */
    private const string RESOLVED_LINK = '01jc0000000000000000000000';

    /** @var string What an issuer or a revocation that fails says. */
    private const string FAILURE = 'The application could not do it.';

    /** @var string A session of the person. */
    private const string SESSION = 'session-1';

    /** @var string Another session of the person. */
    private const string OTHER_SESSION = 'session-2';

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The identity a flow concerns. */
    private IdentityReference $person;

    /** @var bool Whether the application's single-use store has its table. */
    private bool $singleUseCreated = false;

    /**
     * Stop Laravel's clock, which the default clock follows, and configure an
     * application allowing unlinked handoffs. Nothing is bound.
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
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', [self::FLOW_APPLICATION => ['redirect_uri' => self::FLOW_REDIRECT_URI, 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->assertStandalone();
        $this->usePackageTables();

        ApplicationRevocation::create();

        $this->registerFlowRoutes();
        $this->startRecordingEvents();
    }

    /**
     * Drop the application's tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->singleUseCreated) {
            ApplicationSingleUseStore::drop();
        }

        ApplicationRevocation::drop();

        parent::tearDown();
    }

    /**
     * A linker wrapping the store writes a `link` and resolves a later
     * `sign_in`.
     *
     * @return void
     */
    public function testALinkerWrappingTheStoreMakesTheLinksItResolves(): void
    {
        $linker     = $this->bindLinkFlow(new ApplicationLinker(app(LinkStore::class)));
        $connection = $this->openIdConnection('op-linker');
        $start      = $this->startedFlow($connection, 'link', $this->person);
        $code       = $this->completedCode($this->completeFlow($connection, $start));
        $linked     = $this->flowRedeem($connection, 'link', $code, $start['verifier'], $this->person)->assertOk();
        $link       = Link::query()->sole();

        self::assertSame(3, $linker->resolutions, 'At completion, in the judgement and in the admission.');
        self::assertSame([LinkOrigin::LINK_PURPOSE], $linker->created);
        self::assertSame($link->id, $linked->json('link_id'));
        self::assertSame(LinkOrigin::LINK_PURPOSE, $link->provenance);
        self::assertSame($this->person->id, $link->identity_id);

        $signedIn = $this->signedIn($connection);

        self::assertSame(5, $linker->resolutions, 'The sign-in resolves at completion and at redemption too.');
        self::assertSame($this->person->jsonSerialize(), $signedIn['linked']);
        self::assertSame($link->id, $signedIn['link_id']);

        $this->assertOnlyRebound(Fetcher::class, Freshness::class, LinkEligibility::class, Linker::class);
    }

    /**
     * A resolve-only linker answers a `sign_in`, but a `link` and turning
     * linking on are refused.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testAResolverOnlyLinkerAnswersASignInAndRefusesEveryWrite(): void
    {
        $this->bindLinkFlow($this->resolverOnly());

        config()->set('sso.features.domain_linking', true);

        $connection = $this->openIdConnection('op-resolver');
        $signedIn   = $this->signedIn($connection);

        self::assertSame($this->person->jsonSerialize(), $signedIn['linked']);
        self::assertSame(self::RESOLVED_LINK, $signedIn['link_id']);
        self::assertSame(0, Link::query()->count());

        $start = $this->startedFlow($connection, 'link', $this->person);

        try {
            $this->completeThroughTheService($connection, $start);

            self::fail('A link went on over a linker that would ignore it.');
        } catch (\LogicException $exception) {
            self::assertStringStartsWith('A [link] flow needs links its resolver reads', $exception->getMessage());
        }

        try {
            app(LinkingPolicyService::class)->change(
                self::TENANT,
                $connection->id,
                ['enabled' => true, 'issuer_class' => 'single_organization', 'acknowledged' => true],
                Clients::browser(),
            );

            self::fail('Linking went on over a linker that would ignore its rows.');
        } catch (\LogicException $exception) {
            self::assertStringStartsWith('Linking by a verified domain needs links its resolver reads', $exception->getMessage());
        }

        self::assertSame(0, Link::query()->count());
        self::assertFalse(Connection::query()->whereKey($connection->id)->sole()->linking_enabled);
        $this->assertOnlyRebound(Fetcher::class, Freshness::class, LinkEligibility::class, Linker::class);
    }

    /**
     * An issuer wrapping the store is asked in the completion's transaction
     * with the trust version.
     *
     * @return void
     */
    public function testAnIssuerWrappingTheStoreIssuesInsideTheCompletion(): void
    {
        $issuer     = $this->bindIssuer();
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-issuer');
        $start      = $this->startedFlow($connection);
        $code       = $this->completedCode($this->completeFlow($connection, $start));

        self::assertCount(1, $issuer->grants);
        self::assertSame($start['reference'], $issuer->grants[0]->result->requestReference->value);
        self::assertGreaterThan(0, $issuer->levels[0]);
        self::assertSame(hash('sha256', $code), HandoffCode::query()->sole()->code_digest);

        $trustVersion = Connection::query()->whereKey($connection->id)->sole()->trust_version;

        self::assertSame($trustVersion, $issuer->grants[0]->trustVersion);
        self::assertSame($trustVersion, HandoffCode::query()->sole()->trust_version);
        self::assertSame('redeemed', $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->assertOk()->json('status'));
        $this->assertOnlyRebound(HandoffIssuer::class);
    }

    /**
     * An issuer that fails after writing rolls the last transaction back.
     *
     * What the earlier transaction committed stays, the replay record among it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnIssuerThatFailsRollsTheFinalContinuationBack(): void
    {
        $issuer     = $this->bindIssuer();
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-issuer-fails');
        $start      = $this->startedFlow($connection);
        $flows      = $this->flowsVersionOf($connection);

        $issuer->failure = new \RuntimeException(self::FAILURE);

        try {
            $this->completeThroughTheService($connection, $start);

            self::fail('The completion went on.');
        } catch (\RuntimeException $exception) {
            self::assertSame(self::FAILURE, $exception->getMessage());
        }

        $request = AuthorizationRequest::query()->sole();

        self::assertCount(1, $issuer->grants);
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertSame(0, HandoffCode::query()->count());
        self::assertSame($flows, $this->flowsVersionOf($connection));
        self::assertNull($request->completed_at);
        self::assertNotNull($request->verified_at);
        self::assertNotNull($request->consumed_at);
        self::assertSame(1, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());
        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, ResultUnlinked::class]);
        $this->assertOnlyRebound(HandoffIssuer::class);
    }

    /**
     * An issuer holding a reservation binds it to the code, which activates it.
     *
     * @return void
     */
    public function testAnIssuerPreservesAReservationsBinding(): void
    {
        $issuer     = $this->bindIssuer();
        $connection = $this->reservingConnection('op-reservation');
        $start      = $this->startedFlow($connection);
        $code       = $this->completedCode($this->completeFlow($connection, $start, self::verifiedEmail()));
        $reserved   = Link::query()->sole();
        $stored     = HandoffCode::query()->sole();

        self::assertSame(LinkState::RESERVED, $reserved->state);
        self::assertSame($reserved->reservation_id, $issuer->grants[0]->reservationId);
        self::assertSame($stored->id, $reserved->reservation_handoff);
        self::assertSame($stored->expires_at->toIso8601String(), $reserved->reservation_expires_at?->toIso8601String());

        $answer = $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->assertOk();
        $active = Link::query()->sole();

        self::assertSame($reserved->id, $active->id);
        self::assertSame(LinkState::ACTIVE, $active->state);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $active->provenance);
        self::assertSame($active->id, $answer->json('link_id'));
        self::assertSame($this->person->jsonSerialize(), $answer->json('linked'));
        $this->assertEventSequence([
            AuthorizationRequestStarted::class,
            ResultVerified::class,
            HandoffIssued::class,
            LinkCreated::class,
            LinkActivated::class,
            HandoffRedeemed::class,
        ]);
        $this->assertOnlyRebound(Fetcher::class, HandoffIssuer::class, Linker::class, LinkEmailMatcher::class, PrincipalScope::class, TenantMembership::class);
    }

    /**
     * An issuer that answers no reservation reference fails closed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnIssuerThatCannotHoldAReservationRollsTheCompletionBack(): void
    {
        $issuer     = $this->bindIssuer();
        $connection = $this->reservingConnection('op-no-reference');
        $start      = $this->startedFlow($connection);

        $issuer->dropsReference = true;

        try {
            $this->completeThroughTheService($connection, $start, self::verifiedEmail());

            self::fail('The completion went on.');
        } catch (\LogicException $exception) {
            self::assertStringStartsWith('A handoff issuer must store a reservation\'s binding', $exception->getMessage());
        }

        self::assertCount(1, $issuer->grants);
        self::assertSame(0, Link::query()->count());
        self::assertSame(0, HandoffCode::query()->count());
        self::assertNull(AuthorizationRequest::query()->sole()->completed_at);
        $this->assertEventSequence([AuthorizationRequestStarted::class]);
        $this->assertOnlyRebound(Fetcher::class, HandoffIssuer::class, Linker::class, LinkEmailMatcher::class, PrincipalScope::class, TenantMembership::class);
    }

    /**
     * A revocation through the storage connection commits with its change.
     *
     * @return void
     */
    public function testARevocationCommitsWithTheChange(): void
    {
        $revocation = $this->bindRevocation();
        $disabling  = $this->sessionedConnection('idp-revoke-disabling', self::SESSION);
        $satisfying = $this->sessionedConnection('idp-revoke-satisfying', self::OTHER_SESSION);

        $disabled = app(ConnectionLifecycle::class)->disable(self::TENANT, $disabling->id, Clients::browser());

        self::assertSame(ConnectionStatus::DISABLED, $disabled->status);
        self::assertSame([self::OTHER_SESSION], ApplicationRevocation::sessionIds());
        self::assertSame(RevocationScopeKind::CONNECTION, $revocation->scopes[0]->kind);
        self::assertSame(RevocationReason::CONNECTION_DISABLED, $revocation->scopes[0]->reason);
        self::assertSame($disabling->id, $revocation->scopes[0]->connectionId);
        self::assertGreaterThan(0, $revocation->levels[0]);

        $satisfying->forceFill(['has_completed_sign_in' => true])->save();

        ApplicationRevocation::establish(self::SESSION, self::TENANT, self::FLOW_APPLICATION, $disabling->id, null, $this->person, CarbonImmutable::parse(self::FLOW_NOW));

        self::assertTrue(app(EnforcementService::class)->update(self::TENANT, true, [$satisfying->id], Clients::browser())->isChanged());
        self::assertSame([self::OTHER_SESSION], ApplicationRevocation::sessionIds());
        self::assertSame(RevocationScopeKind::TENANT, $revocation->scopes[1]->kind);
        self::assertSame([$satisfying->id], $revocation->scopes[1]->policy?->connectionIds);
        self::assertGreaterThan(0, $revocation->levels[1]);
        $this->assertEventSequence([ConnectionDisabled::class, EnforcementChanged::class]);
        $this->assertOnlyRebound(Freshness::class, SessionRevocation::class);
    }

    /**
     * A revocation that fails after writing rolls back with its change.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationThatFailsRollsBackWithTheChange(): void
    {
        $revocation = $this->bindRevocation();
        $disabling  = $this->sessionedConnection('idp-failing-disabling', self::SESSION);
        $satisfying = $this->sessionedConnection('idp-failing-satisfying', self::OTHER_SESSION);

        $satisfying->forceFill(['has_completed_sign_in' => true])->save();

        $revocation->failure = new \RuntimeException(self::FAILURE);

        $changes = [
            static fn (): mixed => app(ConnectionLifecycle::class)->disable(self::TENANT, $disabling->id, Clients::browser()),
            static fn (): mixed => app(EnforcementService::class)->update(self::TENANT, true, [$satisfying->id], Clients::browser()),
        ];

        foreach ($changes as $change) {
            try {
                $change();

                self::fail('The change went on.');
            } catch (\RuntimeException $exception) {
                self::assertSame(self::FAILURE, $exception->getMessage());
            }
        }

        self::assertCount(2, $revocation->scopes);
        self::assertSame([self::SESSION, self::OTHER_SESSION], ApplicationRevocation::sessionIds());
        self::assertTrue(Connection::query()->whereKey($disabling->id)->sole()->enabled);
        self::assertSame(0, TenantEnforcement::query()->count());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        $this->assertNoEvents();
        $this->assertOnlyRebound(Freshness::class, SessionRevocation::class);
    }

    /**
     * A freshness contract judges the configured age to the second.
     *
     * @return void
     */
    public function testAFreshnessContractDecidesAtTheConfiguredAge(): void
    {
        config()->set('sso.freshness.max_age_seconds.connection_disable', 120);

        $freshness  = new ApplicationFreshness(app(Clock::class));
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-freshness');
        $lifecycle  = app(ConnectionLifecycle::class);
        $now        = CarbonImmutable::parse(self::FLOW_NOW);
        $caller     = new Caller(new IdentityReference('App\Models\User', 'administrator-1'), 'session-1');

        $this->app?->instance(Freshness::class, $freshness);

        $freshness->authenticatedAt = $now;

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $lifecycle->disable(self::TENANT, $connection->id, Clients::browser())->reason);

        $freshness->authenticatedAt = $now->subSeconds(121);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $lifecycle->disable(self::TENANT, $connection->id, Clients::browser(), $caller)->reason);
        self::assertTrue(Connection::query()->whereKey($connection->id)->sole()->enabled);
        $this->assertNoEvents();

        $freshness->authenticatedAt = $now->subSeconds(120);

        self::assertSame(ConnectionStatus::DISABLED, $lifecycle->disable(self::TENANT, $connection->id, Clients::browser(), $caller)->status);
        self::assertSame(array_fill(0, 3, [FreshnessOperation::CONNECTION_DISABLE, 120]), $freshness->asked);
        $this->assertEventSequence([ConnectionDisabled::class]);
        $this->assertOnlyRebound(Freshness::class);
    }

    /**
     * A single-use store on another connection answers every flow but survives
     * rollbacks.
     *
     * @return void
     */
    public function testASingleUseStoreOnAnotherConnectionIsNotUndoneByARollback(): void
    {
        ApplicationSingleUseStore::create();

        $this->singleUseCreated = true;

        $this->app?->instance(SingleUseStore::class, new ApplicationSingleUseStore(app(Clock::class)));

        $connection = $this->flowSamlConnection(self::TENANT, 'idp-single-use');
        $start      = $this->startedFlow($connection);
        $code       = $this->completedCode($this->completeFlow($connection, $start));

        self::assertSame(['authorization_request', ReplayRecord::SAML_ASSERTION], ApplicationSingleUseStore::namespaces());

        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        $admitted = app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, self::FLOW_APPLICATION, $connection->id, $code, $start['verifier'], Clients::browser());

        $database->rollBack();

        self::assertTrue($admitted->isAdmitted());
        self::assertNull(HandoffCode::query()->sole()->redeemed_at);
        self::assertSame(['authorization_request', 'handoff_code', ReplayRecord::SAML_ASSERTION], ApplicationSingleUseStore::namespaces());
        self::assertSame(0, SingleUseKey::query()->count());

        $again = $this->flowRedeem($connection, 'sign_in', $code, $start['verifier']);

        $again->assertStatus(422);

        self::assertSame(FailureReason::REPLAYED->value, $again->json('reason'));
        $this->assertOnlyRebound(SingleUseStore::class);
    }

    /**
     * An attempt limiter counts every step and refuses with its wait when full.
     *
     * @return void
     */
    public function testAnAttemptLimiterCountsEveryFlowInThePackagesPlace(): void
    {
        $limiter = new ApplicationAttemptLimiter(allowing: 1);

        $this->app?->instance(AttemptLimiter::class, $limiter);

        $connection = $this->flowSamlConnection(self::TENANT, 'idp-limiter');

        /** @var array{reference: string, verifier: string, navigation: array{type: string, url: string}} $start */
        $start   = $this->flowStart($connection)->assertOk()->json();
        $refused = $this->flowStart($connection);

        $refused->assertStatus(429);

        self::assertSame(['error' => FailureReason::RATE_LIMITED->value, 'retry_after' => 30], $refused->json());

        $full = $this->completeFlow($connection, $start);

        $full->assertStatus(429);

        self::assertSame('30', (string) $full->baseResponse->headers->get('Retry-After'));
        self::assertNull(AuthorizationRequest::query()->sole()->consumed_at);

        $limiter->allowing = null;

        $code = $this->completedCode($this->completeFlow($connection, $start));

        $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->assertOk();

        $flows = array_map(static fn (mixed $subject): AttemptFlow => $subject->flow, $limiter->subjects);

        self::assertSame([
            AttemptFlow::AUTHORIZATION_REQUEST,
            AttemptFlow::AUTHORIZATION_REQUEST,
            AttemptFlow::COMPLETION,
            AttemptFlow::COMPLETION,
            AttemptFlow::REDEMPTION,
        ], $flows);
        self::assertSame($connection->id, $limiter->subjects[2]->connection);
        self::assertSame(0, RateLimit::query()->count());
        $this->assertOnlyRebound(AttemptLimiter::class);
    }

    /**
     * A fetcher carries the token request; a failed request is `fetch_failed`.
     *
     * @return void
     */
    public function testAFetcherCarriesTheTokenRequestAndItsFailureDecides(): void
    {
        $connection = $this->openIdConnection('op-fetcher');
        $provider   = $this->flowProvider($connection);
        $start      = $this->startedFlow($connection);
        $code       = $this->completedCode($this->completeFlow($connection, $start));

        $this->flowFetcher->assertFetched($provider->endpoint('token'), FetchPurpose::TOKEN);

        self::assertSame(hash('sha256', $code), HandoffCode::query()->sole()->code_digest);

        $provider->respond('token', FetchResult::failed());

        $this->assertFailedFlow($this->completeFlow($connection, $this->startedFlow($connection)), FailureReason::FETCH_FAILED);

        self::assertSame(1, HandoffCode::query()->count());
        $this->assertOnlyRebound(Fetcher::class);
    }

    /**
     * A DNS resolver answers every recheck; a failed lookup fails the run.
     *
     * @return void
     */
    public function testADnsResolverAnswersEveryRecheck(): void
    {
        $dns        = new FakeDnsResolver;
        $connection = $this->makeConnection(['enabled' => true]);
        $token      = str_repeat('ab', 32);

        $this->app?->instance(DnsResolver::class, $dns);

        foreach (['confirmed.example.com', 'absent.example.com', 'failing.example.com'] as $domain) {
            $this->makeDomain($connection, $domain, ['state' => DomainState::VERIFIED, 'verification_token' => $token]);
        }

        $dns->found('_sso-verification.confirmed.example.com', $token)
            ->absent('_sso-verification.absent.example.com')
            ->failing('_sso-verification.failing.example.com');

        Carbon::setTestNow(CarbonImmutable::parse(self::FLOW_NOW)->addHour());

        $code   = Artisan::call('sso:domains:recheck');
        $output = array_values(array_filter(array_map(trim(...), explode("\n", Artisan::output())), static fn (string $line): bool => $line !== ''));

        self::assertSame(1, $code);
        self::assertEqualsCanonicalizing([
            "[suspended] absent.example.com (connection {$connection->id})",
            "[lookup_failed] failing.example.com (connection {$connection->id})",
            'Domains rechecked: confirmed 1, restored 0, suspended 1, still_failing 0, lapsed 0, lookup_failed 1, resolver_threw 0, skipped 0',
        ], $output);

        $dns->assertLookedUp('_sso-verification.confirmed.example.com', 1);
        $dns->assertLookedUp('_sso-verification.absent.example.com', 1);
        $dns->assertLookedUp('_sso-verification.failing.example.com', 1);

        $this->assertOnlyRebound(DnsResolver::class);
    }

    /**
     * A bound clock is the one every time is read from.
     *
     * @return void
     */
    public function testAClockIsWhatEveryTimeIsReadFrom(): void
    {
        $instant = '2026-12-01T00:00:00Z';
        $clock   = new FrozenClock($instant);

        $this->flowClock = new FixedClock($instant);

        $this->app?->instance(Clock::class, $clock);

        $connection = $this->flowSamlConnection(self::TENANT, 'idp-clock');
        $start      = $this->startedFlow($connection);
        $request    = AuthorizationRequest::query()->sole();

        self::assertSame('2026-12-01T00:10:00+00:00', $request->expires_at->toIso8601String());
        self::assertSame('2026-12-01T00:00:00+00:00', $this->recordedEvents()[0]->context()->occurredAt->toIso8601String());

        $this->advanceTime($clock, 599);

        $this->completedCode($this->completeFlow($connection, $start));

        $late = $this->startedFlow($connection);

        $this->advanceTime($clock, 601);

        $this->assertFailedFlow($this->completeFlow($connection, $late), FailureReason::REQUEST_EXPIRED);

        $this->assertOnlyRebound(Clock::class);
    }

    /**
     * An evidence policy decides what the redeemer is given.
     *
     * @return void
     */
    public function testAnEvidencePolicyIsAskedOnceAnIdentityIsEstablished(): void
    {
        $policy = $this->evidencePolicy();

        $this->app?->instance(EvidencePolicy::class, $policy);
        $this->app?->instance(Linker::class, app(LinkStore::class));

        $connection = $this->openIdConnection('op-evidence');
        $subject    = new LinkSubject($this->flowProvider($connection)->issuer, FakeOpenIdProvider::SUBJECT);

        self::assertTrue(app(LinkStore::class)->create($connection, $subject, $this->person, LinkOrigin::LINK_PURPOSE, Clients::browser())->isCreated());

        $other  = static fn (FakeIdToken $token): FakeIdToken => $token->with('sub', 'another-subject');
        $free   = $this->startedFlow($connection);
        $freeBy = $this->admitSignIn($connection, $this->completedCode($this->completeFlow($connection, $free, $other)), $free['verifier']);

        self::assertNull($freeBy->linkedIdentity);
        self::assertNull($freeBy->evidence);
        self::assertSame(0, $policy->asked);

        $start  = $this->startedFlow($connection);
        $answer = $this->admitSignIn($connection, $this->completedCode($this->completeFlow($connection, $start)), $start['verifier']);

        self::assertSame(1, $policy->asked);
        self::assertSame($connection->id, $answer->evidence?->connectionId);
        self::assertSame(self::FLOW_NOW, $answer->evidence->authenticatedAt->utc()->format('Y-m-d\TH:i:s\Z'));
        $this->assertOnlyRebound(EvidencePolicy::class, Fetcher::class, Linker::class);
    }

    /**
     * An eligibility is asked at completion and again at redemption.
     *
     * @return void
     */
    public function testALinkEligibilityIsAskedAtCompletionAndAtRedemption(): void
    {
        $eligibility = $this->eligibilityAnswering(LinkEligibilityVerdict::ELIGIBLE, LinkEligibilityVerdict::INELIGIBLE);

        $this->app?->instance(LinkEligibility::class, $eligibility);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(Linker::class, app(LinkStore::class));

        $connection = $this->openIdConnection('op-eligibility');
        $start      = $this->startedFlow($connection, 'link', $this->person);
        $code       = $this->completedCode($this->completeFlow($connection, $start));

        self::assertSame(1, $eligibility->asked);

        $refused = $this->flowRedeem($connection, 'link', $code, $start['verifier'], $this->person);

        $refused->assertStatus(422);

        self::assertSame(FailureReason::LINK_INELIGIBLE->value, $refused->json('reason'));
        self::assertSame(2, $eligibility->asked);
        self::assertSame(0, Link::query()->count());
        self::assertNotNull(HandoffCode::query()->sole()->redeemed_at);
        $this->assertOnlyRebound(Fetcher::class, Freshness::class, LinkEligibility::class, Linker::class);
    }

    /**
     * A deadline contract decides whether the provider's deadline limits the
     * session.
     *
     * @return void
     */
    public function testAProviderSessionDeadlineContractDecidesTheSessionsLatestEnd(): void
    {
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-deadline');
        $limited    = $this->startedFlow($connection);
        $byDefault  = $this->admitSignIn($connection, $this->completedCode($this->completeFlow($connection, $limited)), $limited['verifier']);

        self::assertSame('2026-11-01T17:30:00+00:00', $byDefault->sessionNotAfter?->toIso8601String());

        $deadline = $this->ignoredDeadline();

        $this->app?->instance(ProviderSessionDeadline::class, $deadline);

        $start  = $this->startedFlow($connection);
        $answer = $this->admitSignIn($connection, $this->completedCode($this->completeFlow($connection, $start)), $start['verifier']);

        self::assertSame(1, $deadline->asked);
        self::assertNull($answer->sessionNotAfter);
        self::assertSame('2026-11-01T17:30:00+00:00', $answer->result?->authenticationContext->providerSessionDeadline?->toIso8601String());
        $this->assertOnlyRebound(ProviderSessionDeadline::class);
    }

    /**
     * Assert the seams named are off their defaults and every other is on its
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
     * Bind the linker with the fresh caller and eligibility a `link` needs.
     *
     * @template TLinker of \SineMacula\Laravel\Sso\Contracts\Linker
     *
     * @param  TLinker  $linker
     * @return TLinker
     */
    private function bindLinkFlow(Linker $linker): Linker
    {
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
        $this->app?->instance(Linker::class, $linker);

        return $linker;
    }

    /**
     * Bind a wrapper of the package's store as the issuer.
     *
     * @return \Tests\Fixtures\Standalone\ApplicationHandoffIssuer
     */
    private function bindIssuer(): ApplicationHandoffIssuer
    {
        $issuer = new ApplicationHandoffIssuer(app(DatabaseHandoffStore::class));

        $this->app?->instance(HandoffIssuer::class, $issuer);

        return $issuer;
    }

    /**
     * Bind the application's revocation and a fresh caller.
     *
     * @return \Tests\Fixtures\Standalone\ApplicationRevocation
     */
    private function bindRevocation(): ApplicationRevocation
    {
        $revocation = new ApplicationRevocation;

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(SessionRevocation::class, $revocation);

        return $revocation;
    }

    /**
     * A usable SAML connection at the host, with one session through it.
     *
     * @param  string  $host
     * @param  string  $session
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function sessionedConnection(string $host, string $session): Connection
    {
        $connection = $this->flowSamlConnection(self::TENANT, $host);

        ApplicationRevocation::establish($session, self::TENANT, self::FLOW_APPLICATION, $connection->id, null, $this->person, CarbonImmutable::parse(self::FLOW_NOW));

        return $connection;
    }

    /**
     * A usable OIDC connection on the fake fetcher.
     *
     * A driver keeps what it was built with, so the fetcher is bound first.
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
     * An OIDC connection set up to reserve a link for the person by a verified
     * domain.
     *
     * @param  string  $host
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function reservingConnection(string $host): Connection
    {
        config()->set('sso.features.domain_linking', true);

        $now = CarbonImmutable::parse(self::FLOW_NOW);

        $this->app?->instance(Linker::class, app(LinkStore::class));
        $this->app?->instance(LinkEmailMatcher::class, new ScriptedEmailMatcher(LinkEmailMatch::exactlyOne($this->person)));
        $this->app?->instance(PrincipalScope::class, new ScriptedPrincipalScope);
        $this->app?->instance(TenantMembership::class, new ScriptedTenantMembership(MembershipStanding::accepted($now->subDays(2))));

        $connection = $this->openIdConnection($host);

        $connection->forceFill([
            'linking_enabled'         => true,
            'linking_issuer_class'    => 'single_organization',
            'linking_acknowledged_at' => $now->subDay(),
        ])->save();

        $this->makeDomain($connection, 'example.com', [
            'state'                    => DomainState::VERIFIED,
            'verified_domain'          => 'example.com',
            'verified_at'              => $now->subDay(),
            'verification_generation'  => 1,
            'last_successful_check_at' => $now,
        ]);

        return $connection;
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
     * Answer the flow through the completion service, so what it throws reaches
     * the test.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  array{navigation: array{url: string}}  $start
     * @param  ?\Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken  $tailor
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function completeThroughTheService(Connection $connection, array $start, ?\Closure $tailor = null): CompletionResult
    {
        $service = app(CompletionService::class);

        if ($connection->protocol === 'saml2') {
            $response = $this->flowSamlResponse($connection)->inResponseTo(self::samlRequestIdOf($start));

            return $service->complete(
                CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
                $connection->id,
                $response->completionRequest(self::relayStateOf($start)),
                Clients::browser(),
            );
        }

        return $service->complete(
            CompletionEndpoint::CALLBACK,
            $connection->id,
            new CompletionRequest('GET', $this->flowGrant($connection, $start, $tailor)->query(), []),
            Clients::browser(),
        );
    }

    /**
     * Admit the code as a `sign_in`, in the transaction a redeemer opens.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $code
     * @param  string  $verifier
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function admitSignIn(Connection $connection, string $code, string $verifier): RedemptionResult
    {
        return DB::connection(StorageConnection::name())->transaction(
            static fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, self::FLOW_APPLICATION, $connection->id, $code, $verifier, Clients::browser()),
        );
    }

    /**
     * The connection's flows version, as it is stored.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return mixed
     */
    private function flowsVersionOf(Connection $connection): mixed
    {
        return Connection::query()->whereKey($connection->id)->value('flows_version');
    }

    /**
     * Move the package's clock and the providers' together, and nothing else.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FrozenClock  $clock
     * @param  int  $seconds
     * @return void
     */
    private function advanceTime(FrozenClock $clock, int $seconds): void
    {
        $clock->advance($seconds);

        $this->flowClock->advance($seconds);
    }

    /**
     * A linker that resolves every result through one link and writes nothing.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\Linker
     */
    private function resolverOnly(): Linker
    {
        return new readonly class ($this->person, self::RESOLVED_LINK) implements Linker {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $linkId
             */
            public function __construct(

                /** Whom every result resolves to. */
                private IdentityReference $identity,

                /** The link it resolves through. */
                private string $linkId,
            ) {}

            /**
             * Resolve the result.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
            {
                unset($result);

                return LinkResolution::linked($this->identity, $this->linkId);
            }
        };
    }

    /**
     * A policy that accepts the result's authentication time and counts calls.
     *
     * @return object{asked: int}
     */
    private function evidencePolicy(): object
    {
        return new class implements EvidencePolicy {
            /** @var int How many times it was asked. */
            public int $asked = 0;

            /**
             * Accept the result's authentication, when it states one.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \Carbon\CarbonImmutable  $now
             * @return ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence
             */
            #[\Override]
            public function evaluate(VerifiedResult $result, SsoConnection $connection, CarbonImmutable $now): ?AcceptedEvidence
            {
                unset($now);

                $this->asked++;

                $authenticatedAt = $result->authenticationContext->authenticatedAt;

                return $authenticatedAt === null ? null : new AcceptedEvidence($connection->getConnectionId(), $authenticatedAt);
            }
        };
    }

    /**
     * An eligibility that gives each answer in turn and counts calls.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict  ...$verdicts
     * @return object{asked: int}
     */
    private function eligibilityAnswering(LinkEligibilityVerdict ...$verdicts): object
    {
        return new class (array_values($verdicts)) implements LinkEligibility {
            /** @var int How many times it was asked. */
            public int $asked = 0;

            /**
             * Constructor.
             *
             * @param  list<\SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict>  $verdicts
             */
            public function __construct(

                /** What it answers, in turn. */
                private readonly array $verdicts,
            ) {}

            /**
             * Count the question, and give the next answer.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict
             */
            #[\Override]
            public function judge(IdentityReference $identity, SsoConnection $connection): LinkEligibilityVerdict
            {
                unset($identity, $connection);

                return $this->verdicts[$this->asked++];
            }
        };
    }

    /**
     * A deadline contract that keeps the session apart from the provider's.
     *
     * @return object{asked: int}
     */
    private function ignoredDeadline(): object
    {
        return new class implements ProviderSessionDeadline {
            /** @var int How many times it was asked. */
            public int $asked = 0;

            /**
             * The deadline limits nothing.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @return \SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect
             */
            #[\Override]
            public function effect(VerifiedResult $result): DeadlineEffect
            {
                unset($result);

                $this->asked++;

                return DeadlineEffect::IGNORED;
            }
        };
    }
}
