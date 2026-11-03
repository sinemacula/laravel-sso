<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Links;

use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
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
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSummary;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Integration\Examples\Application\ExampleDirectory;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/links.md` (SSO-8.3 to SSO-8.5, SSO-8.8,
 * SSO-12.5), on the shared example harness, with the application's own
 * memberships and sessions in its own tables and its link contracts bound by
 * its service provider: the link store resolves a sign-in where the default
 * links nothing; the signed-in user starts a `link` flow, refused while their
 * authentication is stale, and redeems its code as themselves, refused for
 * anyone else; an identity holds two links in a connection and no third; only a
 * member of the connection's tenant links, asked again at redemption; a link a
 * verified domain made is confirmed from a password session and not from the
 * session the link established; and the person lists and removes their links.
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
     * Keep sessions in memory, create the application's tables, register its
     * service provider, make the tenant's OIDC connection, and make the user a
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
     * With the link store bound, a sign-in through a linked subject resolves to
     * the identity; under the package's default nothing does, and the same
     * sign-in is `unlinked`.
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
     * The signed-in user starts a `link` flow for themselves once freshness
     * answers `fresh` for `sso.link.create`, and is refused while it answers
     * `stale`.
     *
     * @return void
     */
    public function testTheSignedInUserStartsALinkFlow(): void
    {
        $user         = $this->user;
        $connectionId = $this->connectionId;

        // @snippet-start links-start
        $identity = new IdentityReference($user->getMorphClass(), (string) $user->getKey());

        $start = app(AuthorizationRequestService::class)->start('web', Purpose::LINK, $connectionId, null, $identity);
        // @snippet-end links-start
        self::assertTrue($start->isStarted());
        self::assertNotNull($start->navigation);
        $this->freshness->assertAsked(FreshnessOperation::LINK_CREATE);

        $this->freshness->staleFor(FreshnessOperation::LINK_CREATE);

        $stale = app(AuthorizationRequestService::class)->start('web', Purpose::LINK, $connectionId, null, $identity);

        self::assertTrue($stale->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $stale->reason);
    }

    /**
     * The endpoint redeems the code for the caller it authenticated, and the
     * link is made for them: the subject now resolves to their identity.
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
        $request  = Request::create('/account/sso/link', 'POST', [
            'connection' => $this->connectionId,
            'code'       => $redirect->code(),
            'verifier'   => self::verifierOf($start),
        ]);

        // @snippet-start links-redeem
        $caller = new IdentityReference($user->getMorphClass(), (string) $user->getKey());

        $result = app(HandoffRedemption::class)->redeem(
            Purpose::LINK,
            'web',
            $request->string('connection')->toString(),
            $request->string('code')->toString(),
            $request->string('verifier')->toString(),
            $caller,
        );
        // @snippet-end links-redeem
        self::assertTrue($result->isRedeemed());
        self::assertEquals($caller, $result->linkedIdentity);
        self::assertSame([$result->linkId], $this->linkIds($caller));
    }

    /**
     * Holding the code and its verifier is not being the person: a caller other
     * than the identity the flow was started for is refused with
     * `identity_mismatch`, and nothing is linked.
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
     * Under the application's limit an identity links two subjects through one
     * connection, and a third is refused with `link_limit_reached`, with
     * nothing written.
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
     * An identity that is no member of the connection's tenant is refused at
     * completion, and a member who leaves the tenant before the code is
     * redeemed is refused at redemption, each with `link_ineligible`.
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
     * A link a verified domain made is not confirmed from the session that link
     * established, `independent_authentication_required`; from a session the
     * person's password established it is, losing its verified domain
     * provenance, and `LinkConfirmed` is reported once.
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
     * The person lists their links and removes one, which another identity's
     * listing never shows; removing it again, or another identity's link, is
     * `link_not_found`, a stale caller is `freshness_required`, and `me`
     * without a caller throws.
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

        // @snippet-start links-list-remove
        $links  = app(LinkService::class);
        $caller = new IdentityReference($user->getMorphClass(), (string) $user->getKey());

        $mine = $links->list('me', $caller);                            // list<LinkSummary>, oldest first
        $some = $links->list(new IdentityReference(User::class, '42')); // another identity's, for administrators

        $result = $links->remove('me', $linkId, $caller, new ActingIdentity($user->getMorphClass(), (string) $user->getKey()));
        // @snippet-end links-list-remove
        self::assertSame([$linkId], self::idsOf($mine));
        self::assertSame([$otherLinkId], self::idsOf($some));
        self::assertArrayNotHasKey('subject', $mine[0]->jsonSerialize());
        self::assertTrue($result->isRemoved());
        self::assertSame($linkId, $result->link?->id);
        self::assertSame([], $links->list('me', $caller));

        // Another identity's link answers as a link that does not exist
        self::assertSame(FailureReason::LINK_NOT_FOUND, $links->remove('me', $otherLinkId, $caller)->reason);
        self::assertSame(FailureReason::LINK_NOT_FOUND, $links->remove('me', $linkId, $caller)->reason);

        $this->freshness->staleFor(FreshnessOperation::LINK_REMOVE);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $links->remove($other, $otherLinkId)->reason);
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
     * Run a whole `link` flow of the identity, the provider asserting the
     * subject given, and answer its redemption.
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

        return $this->redeemLink($this->connectionId, $redirect, $start, $identity);
    }

    /**
     * Verify the tenant's domain, turn linking by it on, and sign the user in
     * by their verified email, which reserves the link the redemption
     * activates.
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

        $claimed = app(DomainService::class)->claim(self::TENANT, $this->connectionId, 'example.com')->domain;

        self::assertNotNull($claimed);

        $this->dns->publishes($claimed);

        self::assertSame(DomainStatus::VERIFIED, app(DomainService::class)->verify(self::TENANT, $this->connectionId, 'example.com')->status);
        self::assertTrue(app(LinkingPolicyService::class)->change(self::TENANT, $this->connectionId, [
            'enabled'      => true,
            'issuer_class' => 'single_organization',
            'acknowledged' => true,
        ])->isChanged());

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
