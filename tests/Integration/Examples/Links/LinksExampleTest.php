<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Links;

use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\LinkConfirmed;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSummary;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Integration\Examples\Application\ExampleDirectory;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * Examples of `docs/guides/links.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkStore::class)]
#[CoversClass(LinkService::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(AuthorizationRequestService::class)]
final class LinksExampleTest extends ExampleTestCase
{
    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's identity provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var \Tests\Integration\Examples\Links\User The signed-in user who links. */
    private User $user;

    /**
     * Create the application's tables and connection, and make the user a
     * member of the tenant.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('session.driver', 'array');

        $schema = Schema::connection(StorageConnection::name());

        $schema->create(Membership::TABLE, static function (Blueprint $table): void {
            $table->id();
            $table->string('identity_type');
            $table->string('identity_id');
            $table->string('tenant_id');
        });

        $schema->create(UserSession::TABLE, static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('identity_type');
            $table->string('identity_id');
            $table->string('sso_link_id')->nullable();
            $table->boolean('sso_domain_link')->default(false);
            $table->string('renewed_link_id')->nullable();
        });

        app()->register(AppServiceProvider::class);

        $this->provider     = new FakeOpenIdProvider(clock: $this->clock);
        $this->connectionId = $this->makeOidcConnection($this->provider);
        $this->user         = new User(['id' => 'person-1']);

        $this->member($this->identity());
    }

    /**
     * Drop the application's tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $schema = Schema::connection(StorageConnection::name());

        $schema->dropIfExists(UserSession::TABLE);
        $schema->dropIfExists(Membership::TABLE);

        parent::tearDown();
    }

    /**
     * The link store resolves a linked sign-in that the default leaves
     * `unlinked`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheLinkStoreResolvesASignInThroughItsLink(): void
    {
        self::assertInstanceOf(LinkStore::class, app(Linker::class));

        $linked = $this->linkThroughFlow($this->provider, $this->connectionId, $this->identity());

        // The package's default links nothing
        app()->singleton(Linker::class, NoLinks::class);

        $start = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);

        self::assertSame(FailureReason::UNLINKED->value, $this->respondAtProvider($this->provider, $this->connectionId, $start)->error);

        app()->register(AppServiceProvider::class, true);

        $signedIn = $this->signInThroughFlow($this->provider, $this->connectionId, 'session-1');

        self::assertTrue($signedIn->isAdmitted());
        self::assertEquals($this->identity(), $signedIn->linkedIdentity);
        self::assertSame($linked->linkId, $signedIn->linkId);
    }

    /**
     * The signed-in user starts a `link` flow when fresh and is refused when
     * stale.
     *
     * @return void
     */
    public function testTheSignedInUserStartsALinkFlow(): void
    {
        $user         = $this->user;
        $connectionId = $this->connectionId;
        $request      = $this->request('/account/sso/link/start');

        $client = Clients::browser();
        // @snippet-start links-start
        // The signed-in user, on the session freshness judges
        $caller = new Caller(new IdentityReference($user->getMorphClass(), (string) $user->getKey()), $request->session()->getId());

        $start = app(AuthorizationRequestService::class)->start('web', Purpose::LINK, $connectionId, $client, null, $caller);
        // @snippet-end links-start
        self::assertTrue($start->isStarted());
        self::assertNotNull($start->navigation);
        $this->freshness->assertAsked(FreshnessOperation::LINK_CREATE);
        self::assertContains($caller, array_column($this->freshness->asked(), 'caller'));

        $this->freshness->staleFor(FreshnessOperation::LINK_CREATE);

        $stale = app(AuthorizationRequestService::class)->start('web', Purpose::LINK, $connectionId, Clients::browser(), null, $caller);

        self::assertTrue($stale->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $stale->reason);
    }

    /**
     * The caller redeems the link code and the link is made for them.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheCallerRedeemsTheLinkCode(): void
    {
        $user     = $this->user;
        $start    = $this->startFlow(Purpose::LINK, $this->connectionId, $this->identity());
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start);
        $request  = $this->request('/account/sso/link', [
            'connection' => $this->connectionId,
            'code'       => $redirect->code(),
            'verifier'   => self::verifierOf($start),
        ]);

        // @snippet-start links-redeem
        // The signed-in user, on the session freshness and confirmation judge
        $caller = new Caller(new IdentityReference($user->getMorphClass(), (string) $user->getKey()), $request->session()->getId());

        $result = app(HandoffRedemption::class)->redeem(
            Purpose::LINK,
            'web',
            $request->string('connection')->toString(),
            $request->string('code')->toString(),
            $request->string('verifier')->toString(),
            ClientContext::fromRequest($request),
            $caller,
        );
        // @snippet-end links-redeem
        self::assertTrue($result->isRedeemed());
        self::assertEquals($caller->identity, $result->linkedIdentity);
        self::assertSame([$result->linkId], $this->linkIds($caller->identity));
    }

    /**
     * A caller other than the flow's identity is refused with
     * `identity_mismatch`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnotherCallerIsRefused(): void
    {
        $start    = $this->startFlow(Purpose::LINK, $this->connectionId, $this->identity());
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start);
        $other    = new IdentityReference(User::class, 'person-2');

        $this->member($other);

        $refused = $this->redeemLink($this->connectionId, $redirect, $start, $other);

        self::assertSame(FailureReason::IDENTITY_MISMATCH, $refused->reason);
        self::assertSame([], $this->linkIds($this->identity()));
        self::assertSame([], $this->linkIds($other));
    }

    /**
     * An identity links two subjects through a connection and is refused a
     * third.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnIdentityHoldsTwoLinksInAConnection(): void
    {
        $first  = $this->linkSubject('subject-a', $this->identity());
        $second = $this->linkSubject('subject-b', $this->identity());

        self::assertTrue($first->isRedeemed());
        self::assertTrue($second->isRedeemed());

        $third = $this->linkSubject('subject-c', $this->identity());

        self::assertSame(FailureReason::LINK_LIMIT_REACHED, $third->reason);
        // Both made at the same frozen instant, so in either order
        self::assertEqualsCanonicalizing([$first->linkId, $second->linkId], $this->linkIds($this->identity()));
    }

    /**
     * A non-member is refused at completion and a member who leaves is refused
     * at redemption.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testOnlyAMemberOfTheTenantLinks(): void
    {
        $stranger = new IdentityReference(User::class, 'person-2');
        $start    = $this->startFlow(Purpose::LINK, $this->connectionId, $stranger);

        self::assertSame(FailureReason::LINK_INELIGIBLE->value, $this->respondAtProvider($this->provider, $this->connectionId, $start)->error);

        $start    = $this->startFlow(Purpose::LINK, $this->connectionId, $this->identity());
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start);

        self::assertTrue($redirect->hasCode());

        // The member leaves the tenant before the code is redeemed
        Membership::on(StorageConnection::name())->where('identity_id', $this->identity()->id)->delete();

        self::assertSame(FailureReason::LINK_INELIGIBLE, $this->redeemLink($this->connectionId, $redirect, $start, $this->identity())->reason);
        self::assertSame([], $this->linkIds($this->identity()));
    }

    /**
     * A domain link is confirmed from a password session, not from the session
     * it established.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAConfirmationNeedsASessionApartFromTheDomainLink(): void
    {
        $sessions = app(Sessions::class);
        $signedIn = $this->signInByVerifiedDomain();
        $session  = $sessions->admitted($signedIn);

        self::assertTrue($sessions->wasEstablishedOnADomainLink($session));

        /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Events\LinkConfirmed> $confirmed */
        $confirmed = new \ArrayObject;

        Event::listen(LinkConfirmed::class, static function (LinkConfirmed $event) use ($confirmed): void {
            $confirmed->append($event);
        });

        $dependent = $this->linkSubject(FakeOpenIdProvider::SUBJECT, $this->identity());

        self::assertSame(FailureReason::INDEPENDENT_AUTHENTICATION_REQUIRED, $dependent->reason);
        self::assertTrue($this->links()[0]->domainProvenance);
        self::assertCount(0, $confirmed);

        // The person signs in again with their password, on a new session
        app(Session::class)->migrate();
        $sessions->signedInWithPassword($this->identity());

        self::assertTrue($this->linkSubject(FakeOpenIdProvider::SUBJECT, $this->identity())->isRedeemed());

        $link = $this->links()[0];

        self::assertSame($signedIn->linkId, $link->id);
        self::assertFalse($link->domainProvenance);
        self::assertSame(LinkState::ACTIVE, $link->state);
        self::assertSame([$this->identity()->id], array_map(static fn (LinkConfirmed $event): ?string => $event->context->identityId, $confirmed->getArrayCopy()));
    }

    /**
     * The person lists and removes their own links only, and a stale caller is
     * refused.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testThePersonListsAndRemovesTheirLinks(): void
    {
        $linkId = (string) $this->linkThroughFlow($this->provider, $this->connectionId, $this->identity())->linkId;
        $other  = new IdentityReference(User::class, '42');

        $this->member($other);

        $otherLinkId = (string) $this->linkSubject('subject-42', $other)->linkId;
        $user        = $this->user;
        $request     = $this->request('/account/sso/links');

        $client = Clients::browser();
        // @snippet-start links-list-remove
        $links  = app(LinkService::class);
        $caller = new Caller(new IdentityReference($user->getMorphClass(), (string) $user->getKey()), $request->session()->getId());

        $mine = $links->list('me', $caller);                            // list<LinkSummary>, oldest first
        $some = $links->list(new IdentityReference(User::class, '42')); // another identity's, for administrators

        $result = $links->remove('me', $linkId, $client, $caller); // freshness judges the caller, who is named as acting
        // @snippet-end links-list-remove
        self::assertSame([$linkId], self::idsOf($mine));
        self::assertSame([$otherLinkId], self::idsOf($some));
        self::assertArrayNotHasKey('subject', $mine[0]->jsonSerialize());
        self::assertTrue($result->isRemoved());
        self::assertSame($linkId, $result->link?->id);
        self::assertSame([], $links->list('me', $caller));

        // Another identity's link answers as a link that does not exist
        self::assertSame(FailureReason::LINK_NOT_FOUND, $links->remove('me', $otherLinkId, Clients::browser(), $caller)->reason);
        self::assertSame(FailureReason::LINK_NOT_FOUND, $links->remove('me', $linkId, Clients::browser(), $caller)->reason);

        $this->freshness->staleFor(FreshnessOperation::LINK_REMOVE);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $links->remove($other, $otherLinkId, Clients::browser())->reason);
        self::assertSame([$otherLinkId], $this->linkIds($other));

        $this->expectException(\InvalidArgumentException::class);

        $links->list('me');
    }

    /**
     * The signed-in user, as the package names them.
     *
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    private function identity(): IdentityReference
    {
        return new IdentityReference($this->user->getMorphClass(), (string) $this->user->getKey());
    }

    /**
     * Make the identity a member of the tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return void
     */
    private function member(IdentityReference $identity): void
    {
        Membership::on(StorageConnection::name())->create(['identity_type' => $identity->type, 'identity_id' => $identity->id, 'tenant_id' => self::TENANT]);
    }

    /**
     * Run a `link` flow of the identity for the subject and redeem it.
     *
     * @param  string  $subject
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Random\RandomException
     */
    private function linkSubject(string $subject, IdentityReference $identity): RedemptionResult
    {
        $start    = $this->startFlow(Purpose::LINK, $this->connectionId, $identity);
        $asserted = static fn (FakeIdToken $token): FakeIdToken => $token->with('sub', $subject);
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start, $asserted);

        return $this->redeemLink($this->connectionId, $redirect, $start, $identity, app(Session::class)->getId());
    }

    /**
     * A request to the path on the application's session.
     *
     * @param  string  $path
     * @param  array<string, string>  $input
     * @return \Illuminate\Http\Request
     */
    private function request(string $path, array $input = []): Request
    {
        $request = Request::create($path, 'POST', $input);

        $request->setLaravelSession(app(Session::class));

        return $request;
    }

    /**
     * Verify the tenant's domain, enable linking by it, and sign the user in by
     * their verified email.
     *
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Random\RandomException
     */
    private function signInByVerifiedDomain(): RedemptionResult
    {
        config()->set('sso.features.domain_linking', true);

        $directory = new ExampleDirectory;

        $this->instance(LinkEmailMatcher::class, $directory);
        $this->instance(PrincipalScope::class, $directory);
        $this->instance(TenantMembership::class, $directory);

        $directory->add($this->identity(), 'person@example.com', self::TENANT, $this->clock->now()->subDays(2));

        $claimed = app(DomainService::class)->claim(self::TENANT, $this->connectionId, 'example.com', Clients::browser())->domain;

        self::assertNotNull($claimed);

        $this->dns->publishes($claimed);

        self::assertSame(DomainStatus::VERIFIED, app(DomainService::class)->verify(self::TENANT, $this->connectionId, 'example.com', Clients::browser())->status);
        self::assertTrue(app(LinkingPolicyService::class)->change(self::TENANT, $this->connectionId, [
            'enabled'      => true,
            'issuer_class' => 'single_organization',
            'acknowledged' => true,
        ], Clients::browser())->isChanged());

        $withEmail = static fn (FakeIdToken $token): FakeIdToken => $token->with('email', 'person@example.com')->with('email_verified', true);
        $start     = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $signedIn  = $this->admitSignIn($this->connectionId, $this->respondAtProvider($this->provider, $this->connectionId, $start, $withEmail), $start, 'session-1');

        self::assertEquals($this->identity(), $signedIn->linkedIdentity);

        return $signedIn;
    }

    /**
     * The signed-in user's links, oldest first.
     *
     * @return list<\SineMacula\Laravel\Sso\Links\LinkSummary>
     */
    private function links(): array
    {
        return app(LinkService::class)->list($this->identity());
    }

    /**
     * The ids of the identity's links, oldest first.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return list<string>
     */
    private function linkIds(IdentityReference $identity): array
    {
        return self::idsOf(app(LinkService::class)->list($identity));
    }

    /**
     * The ids of the links summarised.
     *
     * @param  list<\SineMacula\Laravel\Sso\Links\LinkSummary>  $links
     * @return list<string>
     */
    private static function idsOf(array $links): array
    {
        return array_map(static fn (LinkSummary $link): string => $link->id, $links);
    }
}
