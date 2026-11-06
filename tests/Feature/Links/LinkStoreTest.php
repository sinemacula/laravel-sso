<?php

declare(strict_types = 1);

namespace Tests\Feature\Links;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkCreationStatus;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkCreation;
use SineMacula\Laravel\Sso\Links\LinkEvents;
use SineMacula\Laravel\Sso\Links\LinkHoldings;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Links\LinkSummary;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Linking\ScriptedPrincipalScope;
use Tests\Fixtures\Results\ExampleResults;
use Tests\TestCase;

/**
 * Feature tests for the link store (SSO-8.2 to SSO-8.4, SSO-6.9, SSO-1.5,
 * SSO-10.3): a result resolves only through an active link of its own
 * connection matching its issuer, format and subject byte for byte; a link's
 * last use is stamped at most once a minute; and a creation locks, counts, asks
 * the limit and inserts in that order, refusing a subject already linked or an
 * identity at its limit as values and reporting each link made once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkStore::class)]
#[CoversClass(LinkHoldings::class)]
#[CoversClass(LinkSubject::class)]
#[CoversClass(LinkCreation::class)]
#[CoversClass(LinkSummary::class)]
#[CoversClass(LinkEvents::class)]
final class LinkStoreTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The issuer every subject here is from. */
    private const string ISSUER = 'https://idp.example.com';

    /** @var string The NameID format every SAML subject here has. */
    private const string FORMAT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

    /** @var string The subject linked, with its trailing space. */
    private const string SUBJECT = 'Subject 1 ';

    /** @var string The instant the clock starts at. */
    private const string NOW = '2026-11-01T09:30:00Z';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection links are made through. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The identity links are made for. */
    private IdentityReference $identity;

    /**
     * Bind the clock, create the tables and a connection, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock(self::NOW);

        $this->app?->instance(Clock::class, $this->clock);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['enabled' => true, 'protocol' => 'saml2']);
        $this->identity   = new IdentityReference('user', '1');

        $this->startRecordingEvents();
    }

    /**
     * A result whose connection, issuer, format and subject are linked resolves
     * to the link's identity.
     *
     * @return void
     */
    public function testAnExactlyMatchingResultResolvesToTheIdentity(): void
    {
        $this->linkSubject();

        $resolved = $this->store()->resolve($this->resultFor($this->connection), Clients::browser());

        self::assertSame(['user', '1'], [$resolved->identity?->type, $resolved->identity?->id]);
    }

    /**
     * Another connection, of this tenant or another, with the same issuer and
     * subject, reaches none of this connection's links (SSO-8.2).
     *
     * @return void
     */
    public function testAnotherConnectionWithTheSameIssuerAndSubjectResolvesNothing(): void
    {
        $this->linkSubject();

        $sibling = $this->makeConnection(['enabled' => true, 'protocol' => 'saml2']);
        $foreign = $this->makeConnection(['enabled' => true, 'protocol' => 'saml2', 'tenant_id' => 'tenant-2']);

        self::assertTrue($this->store()->resolve($this->resultFor($sibling), Clients::browser())->isAbsent());
        self::assertTrue($this->store()->resolve($this->resultFor($foreign), Clients::browser())->isAbsent());
        self::assertNotNull($this->store()->resolve($this->resultFor($this->connection), Clients::browser()));
    }

    /**
     * Rows of `[subject, format, issuer]`: a result that differs from the link
     * in one part only.
     *
     * @return iterable<string, array{string, ?string, string}>
     */
    public static function provideNearMisses(): iterable
    {
        yield 'the subject in lower case' => ['subject 1 ', self::FORMAT, self::ISSUER];
        yield 'the subject without its trailing space' => ['Subject 1', self::FORMAT, self::ISSUER];
        yield 'the subject with a second trailing space' => ['Subject 1  ', self::FORMAT, self::ISSUER];
        yield 'no format' => [self::SUBJECT, null, self::ISSUER];
        yield 'another format' => [self::SUBJECT, 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', self::ISSUER];
        yield 'the issuer in upper case' => [self::SUBJECT, self::FORMAT, 'HTTPS://IDP.EXAMPLE.COM'];
        yield 'the issuer with a trailing slash' => [self::SUBJECT, self::FORMAT, self::ISSUER . '/'];
    }

    /**
     * A result that differs from the link in case, a trailing space, the format
     * or the issuer resolves nothing, and stamps nothing (SSO-6.9).
     *
     * @param  string  $subject
     * @param  ?string  $format
     * @param  string  $issuer
     * @return void
     */
    #[DataProvider('provideNearMisses')]
    public function testANearMissResolvesNothing(string $subject, ?string $format, string $issuer): void
    {
        $this->linkSubject();

        self::assertTrue($this->store()->resolve($this->resultFor($this->connection, $subject, $format, $issuer), Clients::browser())->isAbsent());
        self::assertNull(Link::query()->sole()->last_used_at);
    }

    /**
     * Rows of `[attributes]`: a row holding the key of the subject linked, but
     * something else in one part.
     *
     * @return iterable<string, array{array<string, ?string>}>
     */
    public static function provideForgedRows(): iterable
    {
        yield 'another subject' => [['subject' => 'Subject 2 ']];
        yield 'another issuer' => [['issuer' => 'https://other.example.com']];
        yield 'no format' => [['name_id_format' => null]];
        yield 'another format' => [['name_id_format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient']];
    }

    /**
     * A row whose key matches but whose issuer, format or subject does not is
     * not the subject's link, and resolves nothing.
     *
     * @param  array<string, ?string>  $attributes
     * @return void
     */
    #[DataProvider('provideForgedRows')]
    public function testARowWhoseKeyAloneMatchesResolvesNothing(array $attributes): void
    {
        $this->makeLink($this->connection, self::SUBJECT, $attributes + [
            'issuer'         => self::ISSUER,
            'name_id_format' => self::FORMAT,
            'subject_key'    => (new LinkSubject(self::ISSUER, self::SUBJECT, self::FORMAT))->key(),
        ]);

        self::assertTrue($this->store()->resolve($this->resultFor($this->connection), Clients::browser())->isAbsent());
        self::assertNull(Link::query()->sole()->last_used_at);
    }

    /**
     * A reserved link resolves nothing, whether its reservation is live or has
     * expired, and is not stamped.
     *
     * @return void
     */
    public function testAReservedLinkResolvesNothing(): void
    {
        $this->makeLink($this->connection, self::SUBJECT, [
            'issuer'                 => self::ISSUER,
            'name_id_format'         => self::FORMAT,
            'subject_key'            => (new LinkSubject(self::ISSUER, self::SUBJECT, self::FORMAT))->key(),
            'state'                  => LinkState::RESERVED,
            'reservation_expires_at' => CarbonImmutable::parse(self::NOW)->addMinutes(5),
        ]);

        self::assertTrue($this->store()->resolve($this->resultFor($this->connection), Clients::browser())->isReserved());

        $this->clock->advance(600);

        self::assertTrue($this->store()->resolve($this->resultFor($this->connection), Clients::browser())->isAbsent());
        self::assertNull(Link::query()->sole()->last_used_at);
    }

    /**
     * A link made by a verified domain still resolves while its identity holds
     * only principals of the tenant (SSO-8.8).
     *
     * @return void
     */
    public function testADomainProvenanceLinkStillResolves(): void
    {
        $this->app?->instance(PrincipalScope::class, new ScriptedPrincipalScope);

        $this->linkSubject(origin: LinkOrigin::VERIFIED_DOMAIN);

        self::assertTrue(Link::query()->sole()->domain_provenance);

        $resolved = $this->store()->resolve($this->resultFor($this->connection), Clients::browser());

        self::assertSame(['user', '1'], [$resolved->identity?->type, $resolved->identity?->id]);
    }

    /**
     * A suspended link resolves to its identity and link, and to nothing it may
     * sign in as.
     *
     * @return void
     */
    public function testASuspendedLinkResolvesAsSuspended(): void
    {
        $link = $this->makeLink($this->connection, self::SUBJECT, [
            'issuer'         => self::ISSUER,
            'name_id_format' => self::FORMAT,
            'subject_key'    => (new LinkSubject(self::ISSUER, self::SUBJECT, self::FORMAT))->key(),
            'state'          => LinkState::SUSPENDED,
            'provenance'     => LinkOrigin::VERIFIED_DOMAIN,
        ]);

        $resolved = $this->store()->resolve($this->resultFor($this->connection), Clients::browser());

        self::assertTrue($resolved->isSuspended());
        self::assertSame($link->id, $resolved->linkId);
        self::assertNull($resolved->identity);
        self::assertSame(['user', '1'], [$resolved->holder?->type, $resolved->holder?->id]);
        self::assertNull(Link::query()->sole()->last_used_at);
    }

    /**
     * A reserved row that states no expiry is no live reservation.
     *
     * @return void
     */
    public function testAReservedRowWithNoExpiryResolvesNothing(): void
    {
        $this->makeLink($this->connection, self::SUBJECT, [
            'issuer'                 => self::ISSUER,
            'name_id_format'         => self::FORMAT,
            'subject_key'            => (new LinkSubject(self::ISSUER, self::SUBJECT, self::FORMAT))->key(),
            'state'                  => LinkState::RESERVED,
            'reservation_expires_at' => null,
        ]);

        self::assertTrue($this->store()->resolve($this->resultFor($this->connection), Clients::browser())->isAbsent());
    }

    /**
     * A link not made by a verified domain never asks after its identity's
     * principals, and stays active.
     *
     * @return void
     */
    public function testALinkOfAnotherOriginIsNeverSuspendedByScope(): void
    {
        $scope = new ScriptedPrincipalScope;

        $this->app?->instance(PrincipalScope::class, $scope);

        $this->linkSubject();

        self::assertTrue($this->store()->resolve($this->resultFor($this->connection), Clients::browser())->isLinked());
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        self::assertSame([], $scope->asked);
    }

    /**
     * What an identity holds in a connection is read directly: its active and
     * suspended links, and a reservation until it expires.
     *
     * @return void
     */
    public function testWhatAnIdentityHoldsIsCounted(): void
    {
        $now = CarbonImmutable::parse(self::NOW);

        self::assertSame(0, LinkHoldings::count($this->connection->id, $this->identity, $now));

        $this->makeLink($this->connection, 'active');
        $this->makeLink($this->connection, 'suspended', ['state' => LinkState::SUSPENDED]);
        $this->makeLink($this->connection, 'reserved', ['state' => LinkState::RESERVED, 'reservation_expires_at' => $now->addSecond()]);

        self::assertSame(3, LinkHoldings::count($this->connection->id, $this->identity, $now));
        self::assertSame(2, LinkHoldings::count($this->connection->id, $this->identity, $now->addSecond()));
    }

    /**
     * The limit is read directly: what the binding answers, at one and above.
     *
     * @return void
     */
    public function testALimitIsReadDirectly(): void
    {
        $this->bindLimit(1);

        /** @var \SineMacula\Laravel\Sso\Contracts\LinkLimit $limit */
        $limit = app(LinkLimit::class);

        self::assertSame(1, LinkHoldings::limitOf($limit, $this->identity, $this->connection));

        $this->bindLimit(2);

        /** @var \SineMacula\Laravel\Sso\Contracts\LinkLimit $limit */
        $limit = app(LinkLimit::class);

        self::assertSame(2, LinkHoldings::limitOf($limit, $this->identity, $this->connection));
    }

    /**
     * A subject's expired reservation does not stand in the way of its link,
     * and is gone once the link is made.
     *
     * @return void
     */
    public function testAnExpiredReservationIsReplacedByTheLinkMade(): void
    {
        $key      = new LinkSubject(self::ISSUER, self::SUBJECT, self::FORMAT);
        $reserved = $this->makeLink($this->connection, self::SUBJECT, [
            'issuer'                 => self::ISSUER,
            'name_id_format'         => self::FORMAT,
            'subject_key'            => $key->key(),
            'identity_id'            => '2',
            'state'                  => LinkState::RESERVED,
            'reservation_expires_at' => CarbonImmutable::parse(self::NOW)->subSecond(),
        ]);

        self::assertTrue($this->linkSubject()->isCreated());

        $link = Link::query()->sole();

        self::assertNotSame($reserved->id, $link->id);
        self::assertSame(LinkState::ACTIVE, $link->state);
        self::assertSame('1', $link->identity_id);
    }

    /**
     * The bound linking contract is still `NoLinks`, which resolves nothing
     * even for a stored link: the store is bound only by the application.
     *
     * @return void
     */
    public function testNoLinksIsStillTheBoundDefault(): void
    {
        $this->linkSubject();

        /** @var \Illuminate\Foundation\Application $app */
        $app    = $this->app;
        $linker = $app->make(Linker::class);

        self::assertInstanceOf(NoLinks::class, $linker);
        self::assertTrue($linker->resolve($this->resultFor($this->connection), Clients::browser())->isAbsent());
        self::assertTrue($this->store()->resolve($this->resultFor($this->connection), Clients::browser())->isLinked());
    }

    /**
     * A link never used is stamped with the clock's now as it first resolves,
     * and nothing else of it changes.
     *
     * @return void
     */
    public function testTheFirstResolutionStampsTheLastUse(): void
    {
        $this->linkSubject();

        $this->clock->advance(3600);

        $this->store()->resolve($this->resultFor($this->connection), Clients::browser());

        $link = Link::query()->sole();

        self::assertSame('2026-11-01T10:30:00+00:00', $link->last_used_at?->toIso8601String());
        self::assertSame('2026-11-01T09:30:00+00:00', $link->updated_at->toIso8601String());
    }

    /**
     * Rows of `[the purpose of a result that is no sign-in]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose}>
     */
    public static function providePurposesThatAreNoSignIn(): iterable
    {
        yield 'a link' => [Purpose::LINK];
        yield 'a reauthentication' => [Purpose::REAUTHENTICATE];
    }

    /**
     * A resolution for a `link` or a `reauthenticate` resolves the link and is
     * no use of it: `last_used_at` stays exactly as it was, whether never
     * stamped or stamped long ago, so such an operation never looks like a
     * sign-in.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @return void
     */
    #[DataProvider('providePurposesThatAreNoSignIn')]
    public function testOnlyASignInStampsTheLastUse(Purpose $purpose): void
    {
        $this->linkSubject();

        $this->clock->advance(3600);

        self::assertTrue($this->store()->resolve($this->resultFor($this->connection, purpose: $purpose), Clients::browser())->isLinked());

        $unstamped = Link::query()->sole();

        self::assertNull($unstamped->last_used_at);

        $this->store()->resolve($this->resultFor($this->connection), Clients::browser());

        $stamped = Link::query()->sole();

        self::assertSame('2026-11-01T10:30:00+00:00', $stamped->last_used_at?->toIso8601String());

        $this->clock->advance(3600);

        self::assertTrue($this->store()->resolve($this->resultFor($this->connection, purpose: $purpose), Clients::browser())->isLinked());

        $kept = Link::query()->sole();

        self::assertSame('2026-11-01T10:30:00+00:00', $kept->last_used_at?->toIso8601String());
    }

    /**
     * Rows of `[seconds since the last use, stamped again]`: a resolution
     * stamps the last use again only once a minute has passed.
     *
     * @return iterable<string, array{int, bool}>
     */
    public static function provideLastUseAges(): iterable
    {
        yield '59 seconds' => [59, false];
        yield '60 seconds' => [60, true];
        yield '61 seconds' => [61, true];
    }

    /**
     * A link last used less than a minute ago keeps its last use; one used a
     * minute or more ago is stamped with now.
     *
     * @param  int  $seconds
     * @param  bool  $stamped
     * @return void
     */
    #[DataProvider('provideLastUseAges')]
    public function testTheLastUseIsStampedAtMostOnceAMinute(int $seconds, bool $stamped): void
    {
        $this->linkSubject();

        $this->store()->resolve($this->resultFor($this->connection), Clients::browser());

        $this->clock->advance($seconds);

        $resolved = $this->store()->resolve($this->resultFor($this->connection), Clients::browser());

        $expected = $stamped ? CarbonImmutable::parse(self::NOW)->addSeconds($seconds) : CarbonImmutable::parse(self::NOW);

        self::assertNotNull($resolved);
        self::assertSame($expected->toIso8601String(), Link::query()->sole()->last_used_at?->toIso8601String());
    }

    /**
     * A creation makes an active link holding the subject byte for byte under
     * its key, answers its summary, and reports it once with its origin and the
     * whole context.
     *
     * @return void
     */
    public function testACreationMakesAnActiveLinkAndReportsIt(): void
    {
        $creation = $this->store()->create(
            $this->connection,
            new LinkSubject(self::ISSUER, self::SUBJECT, self::FORMAT),
            $this->identity,
            LinkOrigin::LINK_PURPOSE,
            Clients::browser(),
            new ActingIdentity('App\Models\User', '42'),
            'web',
            Purpose::LINK,
            RequestReference::fromString(ExampleResults::REFERENCE),
        );

        self::assertSame(LinkCreationStatus::CREATED, $creation->status);

        $link    = Link::query()->sole();
        $summary = $creation->link;

        self::assertSame([
            'id'                => $link->id,
            'connection_id'     => $this->connection->id,
            'tenant_id'         => 'tenant-1',
            'protocol'          => 'saml2',
            'issuer'            => self::ISSUER,
            'name_id_format'    => self::FORMAT,
            'state'             => 'active',
            'domain_provenance' => false,
            'created_at'        => '2026-11-01T09:30:00Z',
            'last_used_at'      => null,
        ], $summary?->jsonSerialize());

        self::assertMatchesRegularExpression('/^[0-9a-hjkmnp-tv-z]{26}$/', $link->id);
        self::assertSame(self::SUBJECT, $link->subject);
        self::assertSame((new LinkSubject(self::ISSUER, self::SUBJECT, self::FORMAT))->key(), $link->subject_key);
        self::assertSame(['user', '1'], [$link->identity_type, $link->identity_id]);
        self::assertSame(LinkState::ACTIVE, $link->state);
        self::assertFalse($link->domain_provenance);
        self::assertNull($link->reservation_expires_at);
        self::assertNull($link->reservation_reference);

        $this->assertEventSequence([LinkCreated::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(LinkCreated::class, $event);
        self::assertSame(LinkOrigin::LINK_PURPOSE, $event->origin);
        self::assertSame([
            'occurred_at'                 => '2026-11-01T09:30:00.000000Z',
            'connection_id'               => $this->connection->id,
            'connection_tenant_id'        => 'tenant-1',
            'protocol'                    => 'saml2',
            'application'                 => 'web',
            'purpose'                     => 'link',
            'request_reference'           => ExampleResults::REFERENCE,
            'identity_morph_class'        => 'user',
            'identity_id'                 => '1',
            'acting_identity_morph_class' => 'App\Models\User',
            'acting_identity_id'          => '42',
            'principal_morph_class'       => null,
            'principal_id'                => null,
            'tenant_id'                   => null,
            'session_id'                  => null,
            'method'                      => null,
        ], array_diff_key($event->context->toArray(), ['ip' => true, 'user_agent' => true]));
    }

    /**
     * A creation made outside a flow reports no application, purpose, reference
     * or acting identity.
     *
     * @return void
     */
    public function testACreationOutsideAFlowReportsNoFlow(): void
    {
        $this->linkSubject(origin: LinkOrigin::MIGRATION);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(LinkCreated::class, $event);
        self::assertSame(LinkOrigin::MIGRATION, $event->origin);
        self::assertNull($event->context->application);
        self::assertNull($event->context->purpose);
        self::assertNull($event->context->requestReference);
        self::assertNull($event->context->actingIdentityMorphClass);
        self::assertNull($event->context->actingIdentityId);
        self::assertSame($this->connection->id, $event->context->connectionId);
    }

    /**
     * Rows of `[origin, verified domain provenance]`: only a link made by a
     * verified domain carries the provenance.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Sso\Links\Enums\LinkOrigin, bool}>
     */
    public static function provideOrigins(): iterable
    {
        yield 'link_purpose' => [LinkOrigin::LINK_PURPOSE, false];
        yield 'provisioning' => [LinkOrigin::PROVISIONING, false];
        yield 'verified_domain' => [LinkOrigin::VERIFIED_DOMAIN, true];
        yield 'migration' => [LinkOrigin::MIGRATION, false];
    }

    /**
     * The link carries verified domain provenance only when a verified domain
     * made it, and the event carries its origin.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @param  bool  $provenance
     * @return void
     */
    #[DataProvider('provideOrigins')]
    public function testOnlyAVerifiedDomainGivesProvenance(LinkOrigin $origin, bool $provenance): void
    {
        $creation = $this->linkSubject(origin: $origin);

        $event = $this->recordedEvents()[0];

        self::assertSame($provenance, Link::query()->sole()->domain_provenance);
        self::assertSame($provenance, $creation->link?->domainProvenance);
        self::assertInstanceOf(LinkCreated::class, $event);
        self::assertSame($origin, $event->origin);
    }

    /**
     * A subject already linked to another identity is refused, with nothing
     * written or reported.
     *
     * @return void
     */
    public function testASubjectLinkedToAnotherIdentityIsRefused(): void
    {
        $this->linkSubject();
        $this->startRecordingEvents();

        $creation = $this->linkSubject(identity: new IdentityReference('user', '2'));

        self::assertSame(LinkCreationStatus::SUBJECT_ALREADY_LINKED, $creation->status);
        self::assertNull($creation->link);
        self::assertSame(['user', '1'], [Link::query()->sole()->identity_type, Link::query()->sole()->identity_id]);
        $this->assertNoEvents();
    }

    /**
     * A subject already linked to the same identity is refused too, when the
     * identity's limit leaves room.
     *
     * @return void
     */
    public function testASubjectLinkedToTheSameIdentityIsRefused(): void
    {
        $this->bindLimit(2);

        $first = $this->linkSubject();

        $this->startRecordingEvents();

        $creation = $this->linkSubject();

        self::assertSame(LinkCreationStatus::SUBJECT_ALREADY_LINKED, $creation->status);
        self::assertSame($first->link?->id, Link::query()->sole()->id);
        $this->assertNoEvents();
    }

    /**
     * At the default limit of one, a second subject for the identity in the
     * connection is refused, with nothing written or reported.
     *
     * @return void
     */
    public function testTheDefaultLimitAllowsOneLinkPerConnection(): void
    {
        $this->linkSubject();
        $this->startRecordingEvents();

        $creation = $this->linkSubject('Subject 2');

        self::assertSame(LinkCreationStatus::LINK_LIMIT_REACHED, $creation->status);
        self::assertNull($creation->link);
        self::assertSame(1, Link::query()->count());
        $this->assertNoEvents();
    }

    /**
     * A bound limit of two allows two links and refuses the third, and the
     * limit is asked with the identity and the connection.
     *
     * @return void
     */
    public function testABoundLimitOfTwoAllowsTwo(): void
    {
        $asked = $this->bindLimit(2);

        self::assertTrue($this->linkSubject('Subject 1')->isCreated());
        self::assertTrue($this->linkSubject('Subject 2')->isCreated());
        self::assertSame(LinkCreationStatus::LINK_LIMIT_REACHED, $this->linkSubject('Subject 3')->status);
        self::assertSame(2, Link::query()->count());

        self::assertSame(array_fill(0, 3, ['user', '1', $this->connection->id]), $asked->getArrayCopy());
    }

    /**
     * Each link created raises the connection's links version by exactly one,
     * and a creation refused by the unique index or the limit leaves it, so a
     * link's insert always writes the connection's row too.
     *
     * @return void
     */
    public function testEachCreatedLinkRaisesTheLinksVersionByOne(): void
    {
        $this->bindLimit(2);

        $other = $this->makeConnection(['tenant_id' => $this->connection->tenant_id]);

        self::assertSame(0, $this->linksVersion($this->connection));
        self::assertTrue($this->linkSubject('Subject 1')->isCreated());
        self::assertSame(1, $this->linksVersion($this->connection));
        self::assertTrue($this->linkSubject('Subject 2')->isCreated());
        self::assertSame(2, $this->linksVersion($this->connection));
        self::assertSame(LinkCreationStatus::SUBJECT_ALREADY_LINKED, $this->linkSubject('Subject 1', new IdentityReference('user', '2'))->status);
        self::assertSame(LinkCreationStatus::LINK_LIMIT_REACHED, $this->linkSubject('Subject 3')->status);
        self::assertSame(2, $this->linksVersion($this->connection));
        self::assertSame(0, $this->linksVersion($other));
    }

    /**
     * A bound limit below one is a misconfigured binding, named in the
     * exception, and nothing is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALimitBelowOneIsALogicException(): void
    {
        $this->bindLimit(0);

        /** @var \Illuminate\Foundation\Application $app */
        $app     = $this->app;
        $binding = $app->make(LinkLimit::class);

        try {
            $this->store()->create($this->connection, new LinkSubject(self::ISSUER, self::SUBJECT, self::FORMAT), $this->identity, LinkOrigin::LINK_PURPOSE, Clients::browser());
            self::fail('The creation succeeded.');
        } catch (\LogicException $exception) {
            self::assertSame(sprintf('The link limit [%s] answered 0; a link limit is at least one.', $binding::class), $exception->getMessage());
        }

        self::assertSame(0, Link::query()->count());
        $this->assertNoEvents();
    }

    /**
     * Rows of `[seconds from now the reservation expires, counts]`: a
     * reservation counts toward the limit only while it expires after now.
     *
     * @return iterable<string, array{?int, bool}>
     */
    public static function provideReservations(): iterable
    {
        yield 'expired a second ago' => [-1, false];
        yield 'expiring now' => [0, false];
        yield 'expiring in a second' => [1, true];
        yield 'with no expiry' => [null, false];
    }

    /**
     * A reserved link of the identity counts toward the limit only while its
     * reservation expires after now; an active one always counts.
     *
     * @param  ?int  $expiresIn
     * @param  bool  $counts
     * @return void
     */
    #[DataProvider('provideReservations')]
    public function testAReservationCountsOnlyWhileItHasNotExpired(?int $expiresIn, bool $counts): void
    {
        $this->makeLink($this->connection, 'Reserved', [
            'subject_key'            => (new LinkSubject(self::ISSUER, 'Reserved'))->key(),
            'state'                  => LinkState::RESERVED,
            'reservation_expires_at' => $expiresIn === null ? null : CarbonImmutable::parse(self::NOW)->addSeconds($expiresIn),
        ]);

        $creation = $this->linkSubject();

        self::assertSame($counts ? LinkCreationStatus::LINK_LIMIT_REACHED : LinkCreationStatus::CREATED, $creation->status);
        self::assertSame($counts ? 1 : 2, Link::query()->count());
    }

    /**
     * Only the identity's own links in the connection count: another identity's
     * there, and its own in another tenant's connection, do not (SSO-1.5).
     *
     * @return void
     */
    public function testOnlyTheIdentitysLinksInTheConnectionCount(): void
    {
        $foreign = $this->makeConnection(['enabled' => true, 'tenant_id' => 'tenant-2']);

        $this->store()->create($foreign, new LinkSubject(self::ISSUER, 'Elsewhere'), $this->identity, LinkOrigin::LINK_PURPOSE, Clients::browser());
        $this->linkSubject('Another person', identity: new IdentityReference('user', '2'));
        $this->linkSubject('Another type', identity: new IdentityReference('admin', '1'));

        self::assertTrue($this->linkSubject()->isCreated());
        self::assertSame(4, Link::query()->count());
    }

    /**
     * A connection that does not exist is a logic error, with nothing written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMissingConnectionIsALogicException(): void
    {
        $missing = new Connection;

        $missing->forceFill(['id' => '01jbzzzzzzzzzzzzzzzzzzzzzz', 'tenant_id' => 'tenant-1', 'protocol' => 'saml2']);

        try {
            $this->store()->create($missing, new LinkSubject(self::ISSUER, self::SUBJECT), $this->identity, LinkOrigin::LINK_PURPOSE, Clients::browser());
            self::fail('The creation succeeded.');
        } catch (\LogicException $exception) {
            self::assertSame('No connection [01jbzzzzzzzzzzzzzzzzzzzzzz] exists to link through.', $exception->getMessage());
        }

        self::assertSame(0, Link::query()->count());
        $this->assertNoEvents();
    }

    /**
     * A connection of another tenant than the model given claims is not locked,
     * and is a logic error too.
     *
     * @return void
     */
    public function testAConnectionNamingAnotherTenantIsALogicException(): void
    {
        $claimed = new Connection;

        $claimed->forceFill(['id' => $this->connection->id, 'tenant_id' => 'tenant-2', 'protocol' => 'saml2']);

        $this->expectExceptionObject(new \LogicException(sprintf('No connection [%s] exists to link through.', $this->connection->id)));

        $this->store()->create($claimed, new LinkSubject(self::ISSUER, self::SUBJECT), $this->identity, LinkOrigin::LINK_PURPOSE, Clients::browser());
    }

    /**
     * Inside a transaction the application opened, a subject already linked is
     * refused within a savepoint of its own, so the application's transaction
     * goes on, and its later work commits.
     *
     * @return void
     */
    public function testARefusalInsideTheCallersTransactionLeavesItUsable(): void
    {
        $this->linkSubject();
        $this->startRecordingEvents();

        $database = DB::connection(StorageConnection::name());

        $database->transaction(function () use ($database): void {

            self::assertSame(LinkCreationStatus::SUBJECT_ALREADY_LINKED, $this->linkSubject(identity: new IdentityReference('user', '2'))->status);
            self::assertSame(1, $database->transactionLevel());
            self::assertTrue($this->linkSubject('Subject 2', new IdentityReference('user', '2'))->isCreated());
        });

        self::assertSame(2, Link::query()->count());
        $this->assertEventSequence([LinkCreated::class]);
    }

    /**
     * Inside a transaction the application opened, a link made is reported only
     * once it commits, and a rollback leaves no link and reports nothing.
     *
     * @return void
     */
    public function testACreationInsideTheCallersTransactionIsReportedOnCommit(): void
    {
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        self::assertTrue($this->linkSubject()->isCreated());
        $this->assertNoEvents();

        $database->rollBack();

        self::assertSame(0, Link::query()->count());
        $this->assertNoEvents();

        $database->transaction(function (): void {
            self::assertTrue($this->linkSubject()->isCreated());
            $this->assertNoEvents();
        });

        self::assertSame(1, Link::query()->count());
        $this->assertEventSequence([LinkCreated::class]);
    }

    /**
     * Link the subject given (with the format) through the connection, to the
     * identity given or the test's.
     *
     * @param  string  $subject
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @return \SineMacula\Laravel\Sso\Links\LinkCreation
     */
    private function linkSubject(string $subject = self::SUBJECT, ?IdentityReference $identity = null, LinkOrigin $origin = LinkOrigin::LINK_PURPOSE): LinkCreation
    {
        return $this->store()->create($this->connection, new LinkSubject(self::ISSUER, $subject, self::FORMAT), $identity ?? $this->identity, $origin, Clients::browser());
    }

    /**
     * The connection's links version, as stored.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return int
     */
    private function linksVersion(Connection $connection): int
    {
        return Connection::query()->findOrFail($connection->id)->links_version;
    }

    /**
     * Bind a link limit that answers the most given, and answer each identity
     * and connection it is asked about, in order.
     *
     * @param  int  $max
     * @return \ArrayObject<int, array{0: string, 1: string, 2: string}>
     */
    private function bindLimit(int $max): \ArrayObject
    {
        /** @var \ArrayObject<int, array{0: string, 1: string, 2: string}> $asked */
        $asked = new \ArrayObject;

        $this->app?->instance(LinkLimit::class, new readonly class ($max, $asked) implements LinkLimit {
            /**
             * Constructor.
             *
             * @param  int  $max
             * @param  \ArrayObject<int, array{0: string, 1: string, 2: string}>  $asked
             */
            public function __construct(

                /** The most links it allows. */
                private int $max,

                /** Each identity and connection asked about. */
                private \ArrayObject $asked,
            ) {}

            /**
             * Record the question and answer the most set.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return int
             */
            #[\Override]
            public function maxLinks(IdentityReference $identity, SsoConnection $connection): int
            {
                $this->asked->append([$identity->type, $identity->id, $connection->getConnectionId()]);

                return $this->max;
            }
        });

        return $asked;
    }

    /**
     * A verified result through the connection, with the subject, format and
     * issuer given or those linked.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $subject
     * @param  ?string  $format
     * @param  string  $issuer
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private function resultFor(
        Connection $connection,
        string $subject = self::SUBJECT,
        ?string $format = self::FORMAT,
        string $issuer = self::ISSUER,
        Purpose $purpose = Purpose::SIGN_IN,
    ): VerifiedResult {
        return new VerifiedResult(
            $issuer,
            $subject,
            $format,
            $connection->id,
            $connection->tenant_id,
            $connection->protocol,
            'web',
            $purpose,
            RequestReference::fromString(ExampleResults::REFERENCE),
            [],
            false,
            new AuthenticationContext,
        );
    }

    /**
     * The link store, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Links\LinkStore
     */
    private function store(): LinkStore
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(LinkStore::class);
    }
}
