<?php

declare(strict_types = 1);

namespace Tests\Integration\Standalone;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\DomainClaimed;
use SineMacula\Laravel\Sso\Events\DomainVerified;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\LinkActivated;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\ReauthenticationCompleted;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\ReservationActivation;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningResult;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\FlowRoutes;
use Tests\Concerns\RecordsEventSequences;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\Fixtures\Standalone\ApplicationRevocation;
use Tests\Fixtures\Standalone\ApplicationSeams;
use Tests\Fixtures\Standalone\ApplicationSingleUseStore;
use Tests\StandaloneTestCase;

/**
 * A complete application integration, with no sibling (FEATURES "No dependency
 * on a sibling": events are the integration surface, routes are the
 * application's): every seam an application stands behind bound at once, by
 * `ApplicationSeams`, and each purpose run from start to redemption over both
 * protocols, with provisioning through the helper, enforcement with revocation,
 * and linking by a verified domain from reservation to activation.
 *
 * What a sibling would consume is asserted from the events alone, with nothing
 * queried back from the package's tables, so each event is shown to carry
 * enough to act on, and nothing that must not leave a flow. What the
 * application's own adapters kept (its sessions, its store, its limiter) is
 * theirs to read.
 *
 * This shows the seams join up. It is not what shows the package stands alone:
 * `DefaultBindingsFlowsTest` and `DefaultBindingsRefusalsTest` are, and stand
 * without any of these.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequestService::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(ProvisioningHelper::class)]
#[CoversClass(EnforcementService::class)]
#[CoversClass(ReservationActivation::class)]
final class ApplicationIntegrationTest extends StandaloneTestCase
{
    use FlowRoutes, RecordsEventSequences;

    /** @var string The tenant of every connection. */
    private const string TENANT = 'tenant-1';

    /** @var string A protocol's name, as a row of the data provider gives it. */
    private const string SAML = 'saml2';

    /** @var string A protocol's name, as a row of the data provider gives it. */
    private const string OIDC = 'oidc';

    /** @var string The email an identity provider asserts, of the claimed domain. */
    private const string EMAIL = 'person@example.com';

    /** @var string The session a `sign_in` establishes. */
    private const string SESSION = 'session-1';

    /** @var string When that session last authenticated, before a `reauthenticate`. */
    private const string EARLIER = '2026-11-01T08:00:00Z';

    /** @var string The format of the SAML attribute the email is read from. */
    private const string BASIC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The identity the application knows. */
    private IdentityReference $person;

    /** @var \Tests\Fixtures\Standalone\ApplicationSeams What the application binds. */
    private ApplicationSeams $seams;

    /**
     * Configure the protocols, the endpoints and the application; create the
     * package's tables, the application's own, and the routes it adds; bind
     * every seam, with a caller who has just authenticated; and record events.
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
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', [self::FLOW_APPLICATION => ['redirect_uri' => self::FLOW_REDIRECT_URI, 'external_sign_in' => true]]);

        $this->assertStandalone();
        $this->createEveryTable();

        ApplicationRevocation::create();
        ApplicationSingleUseStore::create();

        $this->registerFlowRoutes();

        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $this->seams = new ApplicationSeams($app, self::FLOW_NOW, $this->flowFetcher);

        $this->seams->freshness->authenticatedAt = $this->seams->clock->now();

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
        ApplicationSingleUseStore::drop();
        ApplicationRevocation::drop();

        $this->dropEveryTable();

        parent::tearDown();
    }

    /**
     * Every seam is what the application bound, those it leaves alone are on
     * their defaults, and no sibling came with it.
     *
     * @return void
     */
    public function testTheApplicationBindsEverySeam(): void
    {
        $this->assertStandalone();

        foreach ($this->seams->seams() as $seam => $bound) {
            self::assertSame($bound, $this->app?->make($seam), "{$seam} is not what the application bound.");
        }

        foreach (array_diff_key(self::DEFAULT_BINDINGS, $this->seams->seams()) as $seam => $default) {
            self::assertInstanceOf($default, $this->app?->make($seam), "{$seam} is not bound to its default.");
        }
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
     * A `link`, then a `sign_in` through the link it made, then a
     * `reauthenticate` of the session that established, from start to
     * redemption: each reported in full by events, and what each adapter was
     * asked is what it answered.
     *
     * @param  string  $protocol
     * @return void
     */
    #[DataProvider('provideProtocols')]
    public function testEachPurposeFromStartToRedemption(string $protocol): void
    {
        $connection = $this->connectionOver($protocol, 'purposes');

        $this->assertALink($connection);

        $linkId = $this->assertASignIn($connection);

        $this->assertAReauthentication($connection, $linkId, $protocol);

        self::assertCount(9, $this->seams->limiter->subjects, 'Each flow counts its start, its completion and its redemption.');
        self::assertCount(3, $this->seams->issuer->grants);
        self::assertSame([LinkOrigin::LINK_PURPOSE], $this->seams->linker->created);

        $held = ['authorization_request' => 3, 'handoff_code' => 3];

        self::assertSame($protocol === self::SAML ? [...$held, 'saml_assertion' => 3] : $held, array_count_values(ApplicationSingleUseStore::namespaces()));
    }

    /**
     * A `sign_in` of a subject nobody holds is offered to a listener, which
     * links a new identity through the helper with the grant and nothing it
     * read back; the completion then finishes through that link, and it
     * redeems. The listener is on `Contracts\SsoEvent`, so it runs after the
     * recording listener, which then sees the offer before what is made of it;
     * one on the event's own class would run first, and record the other way.
     *
     * @param  string  $protocol
     * @return void
     */
    #[DataProvider('provideProtocols')]
    public function testProvisioningThroughTheHelper(string $protocol): void
    {
        $connection = $this->connectionOver($protocol, 'provisioning');
        $new        = new IdentityReference('App\Models\User', 'person-new');

        /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Provisioning\ProvisioningResult> $answers */
        $answers = new \ArrayObject;

        Event::listen(SsoEvent::class, static function (SsoEvent $event) use ($new, $answers): void {

            if (!$event instanceof ResultUnlinked) {
                return;
            }

            $answers->append(DB::connection(StorageConnection::name())->transaction(
                static fn (): ProvisioningResult => app(ProvisioningHelper::class)->link($event->grant, $event->result, $new),
            ));
        });

        $start = $this->startedFlow($connection);
        $code  = $this->completedCode($this->completeFlow($connection, $start));

        self::assertCount(1, $answers);
        self::assertTrue($answers->getArrayCopy()[0]->isCreated());

        $answer = $this->admitted($connection, $code, $start['verifier']);

        self::assertTrue($answer->isAdmitted());
        self::assertTrue($new->is($answer->linkedIdentity ?? $this->person));
        self::assertSame([LinkOrigin::PROVISIONING], $this->seams->linker->created);

        $this->assertEventSequence([
            AuthorizationRequestStarted::class,
            ResultVerified::class,
            ResultUnlinked::class,
            LinkCreated::class,
            HandoffIssued::class,
            HandoffRedeemed::class,
        ]);

        $created = $this->recordedEvents()[3];

        self::assertInstanceOf(LinkCreated::class, $created);
        self::assertSame(LinkOrigin::PROVISIONING, $created->origin);
        $this->assertConcerns($created, $connection, Purpose::SIGN_IN, $start['reference'], $new);
        $this->assertConcerns($this->recordedEvents()[5], $connection, Purpose::SIGN_IN, $start['reference'], $new);
        $this->assertLeaksNothing($code, $start['verifier']);
    }

    /**
     * A tenant turns enforcement on: the revocation removes, in the change's
     * transaction, the session the rule no longer allows, and the event carries
     * the rule. A sign-in through another connection is then refused, and one
     * through the satisfying connection carries the event's version.
     *
     * @return void
     */
    public function testEnforcementWithRevocation(): void
    {
        config()->set('sso.features.enforcement', true);

        $satisfying = $this->connectionOver(self::SAML, 'enforced');
        $outside    = $this->connectionOver(self::OIDC, 'outside');
        $actor      = new ActingIdentity('App\Models\User', 'administrator-1');

        $this->linkAndSignIn($satisfying, 'session-satisfying');
        $this->linkAndSignIn($outside, 'session-outside');

        self::assertSame(['session-outside', 'session-satisfying'], ApplicationRevocation::sessionIds());

        $this->startRecordingEvents();

        $result = app(EnforcementService::class)->update(self::TENANT, true, [$satisfying->id], $actor);

        self::assertTrue($result->isChanged());
        self::assertSame(['session-satisfying'], ApplicationRevocation::sessionIds());

        $scope = $this->seams->sessions->scopes[0];

        self::assertSame(RevocationScopeKind::TENANT, $scope->kind);
        self::assertSame([$satisfying->id], $scope->policy?->connectionIds);
        self::assertGreaterThan(0, $this->seams->sessions->levels[0]);

        $this->assertEventSequence([EnforcementChanged::class]);

        $changed = $this->recordedEvents()[0];

        self::assertInstanceOf(EnforcementChanged::class, $changed);
        self::assertTrue($changed->enabled);
        self::assertSame([$satisfying->id], $changed->connectionIds);
        self::assertNull($changed->previousVersion);
        self::assertSame(self::TENANT, $changed->context->tenantId);
        self::assertSame($actor->id, $changed->context->actingIdentityId);

        $this->startRecordingEvents();

        $this->assertFailedFlow($this->completeFlow($outside, $this->startedFlow($outside)), FailureReason::ENFORCEMENT_UNSATISFIED);

        $failure = $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::ENFORCEMENT_UNSATISFIED);

        self::assertSame($outside->id, $failure->context->connectionId);

        $start = $this->startedFlow($satisfying);
        $code  = $this->completedCode($this->completeFlow($satisfying, $start));

        self::assertSame($changed->version, $this->flowRedeem($satisfying, 'sign_in', $code, $start['verifier'])->assertOk()->json('enforcement_version'));
    }

    /**
     * Linking by a verified domain, as a tenant's administrator and the person
     * do it: the domain claimed and verified through the resolver, the policy
     * turned on, then a `sign_in` that reserves the link for the person the
     * application matched, and a redemption that activates it.
     *
     * @param  string  $protocol
     * @return void
     */
    #[DataProvider('provideProtocols')]
    public function testLinkingByAVerifiedDomainFromReservationToActivation(string $protocol): void
    {
        config()->set('sso.features.domain_linking', true);

        $connection = $this->connectionOver($protocol, 'linking');

        $this->verifyTheDomain($connection);
        $this->turnLinkingOn($connection, $protocol);

        $this->assertEventSequence([DomainClaimed::class, DomainVerified::class, ConnectionUpdated::class]);
        $this->startRecordingEvents();

        $this->seams->matcher->match = LinkEmailMatch::exactlyOne($this->person);

        $start    = $this->startedFlow($connection);
        $code     = $this->completedCode($this->completeFlow($connection, $start, $protocol === self::SAML ? self::emailInAnAssertion() : self::emailInAnIdToken()));
        $reserved = $this->seams->issuer->grants[0]->reservationId;

        self::assertNotNull($reserved);
        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, HandoffIssued::class]);

        $answer = $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->assertOk();

        self::assertSame($this->person->jsonSerialize(), $answer->json('linked'));
        self::assertSame([], $this->seams->linker->created);
        self::assertSame(self::EMAIL, $this->seams->matcher->queries[0]->email());

        $this->assertEventSequence([
            AuthorizationRequestStarted::class,
            ResultVerified::class,
            HandoffIssued::class,
            LinkCreated::class,
            LinkActivated::class,
            HandoffRedeemed::class,
        ]);

        $created   = $this->recordedEvents()[3];
        $activated = $this->recordedEvents()[4];

        self::assertInstanceOf(LinkCreated::class, $created);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $created->origin);
        self::assertInstanceOf(LinkActivated::class, $activated);
        self::assertSame($answer->json('link_id'), $activated->linkId);
        $this->assertConcerns($activated, $connection, Purpose::SIGN_IN, $start['reference'], $this->person);
        $this->assertLeaksNothing($code, $start['verifier']);
    }

    /**
     * A `link` for the person: its events carry whom it was made for, and the
     * caller was asked about twice, at its start and its redemption.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     */
    private function assertALink(Connection $connection): void
    {
        $start = $this->startedFlow($connection, 'link', $this->person);
        $code  = $this->completedCode($this->completeFlow($connection, $start));
        $made  = $this->flowRedeem($connection, 'link', $code, $start['verifier'], $this->person)->assertOk();

        self::assertSame('redeemed', $made->json('status'));
        self::assertSame(array_fill(0, 2, [FreshnessOperation::LINK_CREATE, 300]), $this->seams->freshness->asked);

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, HandoffIssued::class, LinkCreated::class, HandoffRedeemed::class]);

        $created = $this->recordedEvents()[3];

        self::assertInstanceOf(LinkCreated::class, $created);
        self::assertSame(LinkOrigin::LINK_PURPOSE, $created->origin);
        $this->assertConcerns($created, $connection, Purpose::LINK, $start['reference'], $this->person);
        $this->assertConcerns($this->recordedEvents()[4], $connection, Purpose::LINK, $start['reference'], $this->person);
        $this->assertLeaksNothing($code, $start['verifier']);
    }

    /**
     * A `sign_in` through the link: it writes its session in the redemption's
     * transaction, with the evidence the application's policy accepted, and the
     * provider's deadline limiting nothing, as the application says. Answers
     * the link it established.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return string
     */
    private function assertASignIn(Connection $connection): string
    {
        $this->startRecordingEvents();

        $start  = $this->startedFlow($connection);
        $code   = $this->completedCode($this->completeFlow($connection, $start));
        $answer = $this->admitted($connection, $code, $start['verifier'], self::SESSION);

        self::assertTrue($answer->isAdmitted());
        self::assertTrue($this->person->is($answer->linkedIdentity ?? new IdentityReference('nobody', 'nobody')));
        self::assertSame($connection->id, $answer->evidence?->connectionId);
        self::assertNull($answer->sessionNotAfter);
        self::assertSame([self::SESSION], ApplicationRevocation::sessionIds());

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, HandoffIssued::class, HandoffRedeemed::class]);
        $this->assertConcerns($this->recordedEvents()[3], $connection, Purpose::SIGN_IN, $start['reference'], $this->person);
        $this->assertLeaksNothing($code, $start['verifier']);

        return (string) $answer->linkId;
    }

    /**
     * A `reauthenticate` of the session: its time is renewed through the
     * application's contract, with the evidence accepted, and its events name
     * the session a sibling would act on.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $linkId
     * @param  string  $protocol
     * @return void
     */
    private function assertAReauthentication(Connection $connection, string $linkId, string $protocol): void
    {
        self::assertNotSame('', $linkId);

        $this->startRecordingEvents();

        $start = $this->startedFlow($connection, 'reauthenticate', $this->person, self::SESSION);
        $code  = $this->completedCode($this->completeFlow($connection, $start));

        $this->flowRedeem($connection, 'reauthenticate', $code, $start['verifier'])->assertOk();

        // The fake provider's SAML statement is a minute old; its ID token, now
        self::assertSame($protocol === self::SAML ? '2026-11-01T09:29:00Z' : self::FLOW_NOW, ApplicationRevocation::authenticatedAt(self::SESSION));
        self::assertCount(1, $this->seams->sessions->renewals);
        self::assertSame($connection->id, $this->seams->sessions->renewals[0]?->connectionId);

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, HandoffIssued::class, HandoffRedeemed::class, ReauthenticationCompleted::class]);

        $completed = $this->recordedEvents()[4];

        $this->assertConcerns($completed, $connection, Purpose::REAUTHENTICATE, $start['reference'], $this->person);

        self::assertSame(self::SESSION, $completed->context()->sessionId);
        $this->assertLeaksNothing($code, $start['verifier']);
    }

    /**
     * A usable connection over the protocol at a host of its own.
     *
     * @param  string  $protocol
     * @param  string  $host
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connectionOver(string $protocol, string $host): Connection
    {
        return $protocol === self::SAML
            ? $this->flowSamlConnection(self::TENANT, "idp-{$host}")
            : $this->flowOidcConnection(self::TENANT, "op-{$host}");
    }

    /**
     * Link the person through the connection and sign them in, writing the
     * session.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $session
     * @return void
     */
    private function linkAndSignIn(Connection $connection, string $session): void
    {
        $this->linkedThroughFlow($connection, $this->person);

        $start = $this->startedFlow($connection);
        $code  = $this->completedCode($this->completeFlow($connection, $start));

        self::assertTrue($this->admitted($connection, $code, $start['verifier'], $session)->isAdmitted());
    }

    /**
     * Admit the code as a `sign_in`, in the transaction a redeemer opens,
     * writing the session named in it, as a sign-in does once it answers
     * `redeemed`.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $code
     * @param  string  $verifier
     * @param  ?string  $session
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function admitted(Connection $connection, string $code, string $verifier, ?string $session = null): RedemptionResult
    {
        return DB::connection(StorageConnection::name())->transaction(static function () use ($connection, $code, $verifier, $session): RedemptionResult {

            $answer = app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, self::FLOW_APPLICATION, $connection->id, $code, $verifier);

            if ($session !== null && $answer->linkedIdentity !== null) {
                ApplicationRevocation::establish(
                    $session,
                    $connection->tenant_id,
                    self::FLOW_APPLICATION,
                    $connection->id,
                    $answer->linkId,
                    $answer->linkedIdentity,
                    CarbonImmutable::parse(self::EARLIER),
                );
            }

            return $answer;
        });
    }

    /**
     * Claim the email's domain for the connection, publish its record and
     * verify it through the helpers, which ask the application's freshness and
     * resolver.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     */
    private function verifyTheDomain(Connection $connection): void
    {
        $domains = app(DomainService::class);
        $claimed = $domains->claim(self::TENANT, $connection->id, 'example.com');

        self::assertSame(DomainStatus::CLAIMED, $claimed->status);
        self::assertNotNull($claimed->domain);

        $this->seams->dns->publishes($claimed->domain);

        self::assertSame(DomainStatus::VERIFIED, $domains->verify(self::TENANT, $connection->id, 'example.com')->status);

        $this->seams->dns->assertLookedUp($claimed->domain->recordName, 1);
    }

    /**
     * Turn linking on for the connection through the helper, classifying its
     * issuer as one organisation's, with the attribute a SAML connection reads
     * the email from.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $protocol
     * @return void
     */
    private function turnLinkingOn(Connection $connection, string $protocol): void
    {
        $attribute = $protocol === self::SAML ? ['saml_attribute' => 'email', 'saml_attribute_format' => self::BASIC] : [];
        $changed   = app(LinkingPolicyService::class)->change(self::TENANT, $connection->id, [
            'enabled'      => true,
            'issuer_class' => 'single_organization',
            'acknowledged' => true,
            ...$attribute,
        ]);

        self::assertTrue($changed->isChanged());
    }

    /**
     * What has an assertion state the email, as a named attribute.
     *
     * @return \Closure(\SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse): \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private static function emailInAnAssertion(): \Closure
    {
        $asserted = ['attributes' => ['email' => [self::EMAIL]], 'attribute_name_format' => self::BASIC];

        return static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with($asserted);
    }

    /**
     * What has an ID token assert the email, verified.
     *
     * @return \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken
     */
    private static function emailInAnIdToken(): \Closure
    {
        return static fn (FakeIdToken $token): FakeIdToken => $token->with('email', self::EMAIL)->with('email_verified', true);
    }

    /**
     * Assert the event says, on its own, which flow and whom it concerns, as a
     * sibling reads it.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $reference
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return void
     */
    private function assertConcerns(SsoEvent $event, Connection $connection, Purpose $purpose, string $reference, IdentityReference $identity): void
    {
        $context = $event->context();

        self::assertSame($connection->id, $context->connectionId);
        self::assertSame(self::TENANT, $context->tenantId);
        self::assertSame($connection->protocol, $context->protocol);
        self::assertSame(self::FLOW_APPLICATION, $context->application);
        self::assertSame($purpose->value, $context->purpose);
        self::assertSame($reference, $context->requestReference);
        self::assertSame($identity->type, $context->identityMorphClass);
        self::assertSame($identity->id, $context->identityId);
    }

    /**
     * Assert no event recorded carries what must not leave a flow, in its
     * context or as it serialises: the code, the verifier, the subject or the
     * email the provider asserted.
     *
     * @param  string  ...$values
     * @return void
     */
    private function assertLeaksNothing(string ...$values): void
    {
        foreach ($this->recordedEvents() as $event) {

            $record = json_encode([$event->context()->toArray(), $event], JSON_THROW_ON_ERROR);

            foreach ([...$values, self::EMAIL, FakeOpenIdProvider::SUBJECT, 'alice'] as $value) {
                self::assertStringNotContainsString($value, $record, $event::class . ' carries what must not leave a flow.');
            }
        }
    }
}
