<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\ManagingConnections;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ViewErrorBag;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\ConnectionSummary;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\SubjectMigration;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\ConnectionCreated;
use SineMacula\Laravel\Sso\Events\ConnectionDeleted;
use SineMacula\Laravel\Sso\Events\ConnectionDisabled;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\LinkRemoved;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use SineMacula\Laravel\Sso\Secrets\MaskedSecret;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/managing-connections.md` (SSO-2.11 to SSO-2.13,
 * SSO-4.5, SSO-12.5), on the shared example harness, with the application's own
 * tenant, administrator and session revocation: the services are resolved from
 * the container; the create endpoint makes a disabled connection from the
 * `google` preset, and sends an invalid form back with each violation under its
 * setting; an update changes a setting, removes another, renames the connection
 * and changes its mapping, refused while the caller is stale; a connection is
 * read and the tenant's listed, oldest first; one is enabled, disabled with its
 * sessions revoked, and deleted, each refused while the caller is stale; and a
 * migration to a new issuer relinks two links and removes two, refused while a
 * link is left out, after which the relinked person signs in through their new
 * subject and the leaver does not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-type EndpointInput array{
 *     connections: \SineMacula\Laravel\Sso\Connections\ConnectionService,
 *     tenant: \Tests\Integration\Examples\ManagingConnections\Tenant,
 *     user: \Tests\Integration\Examples\ManagingConnections\User,
 *     request: \Illuminate\Http\Request
 * }
 *
 * @internal
 */
#[CoversClass(ConnectionService::class)]
#[CoversClass(ConnectionLifecycle::class)]
#[CoversClass(SubjectMigration::class)]
final class ManagingConnectionsExampleTest extends ExampleTestCase
{
    /** @var string The issuer the tenant's identity provider moves to. */
    private const string NEW_ISSUER = 'https://login.acme.example';

    /** @var \Tests\Integration\Examples\ManagingConnections\Tenant The tenant whose connections are managed. */
    private Tenant $tenant;

    /** @var \Tests\Integration\Examples\ManagingConnections\User The administrator who manages them. */
    private User $user;

    /** @var \Tests\Integration\Examples\ManagingConnections\RevokedSessions The application's session revocation. */
    private RevokedSessions $revocations;

    /**
     * Keep sessions in memory, declare the application's custom mapping target,
     * and bind its session revocation.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('session.driver', 'array');
        config()->set('sso.mapping.custom_attributes', ['department']);

        $this->tenant      = new Tenant(self::TENANT);
        $this->user        = new User(['id' => 'admin-1']);
        $this->revocations = new RevokedSessions;

        $this->instance(SessionRevocation::class, $this->revocations);
    }

    /**
     * The three services resolve from the container, and each scopes its calls
     * to the tenant: another tenant's connection, or one whose tenant id
     * differs only in case, is answered as an unknown one.
     *
     * @return void
     */
    public function testResolvesTheServicesScopedToTheTenant(): void
    {
        [$connections, $lifecycle, $migration] = self::services();

        $connectionId = $this->createdId();

        self::assertSame($connectionId, $connections->get($this->tenant->id, $connectionId)?->id);
        self::assertNull($connections->get('Tenant-1', $connectionId));
        self::assertSame([], $connections->list('tenant-2'));
        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $lifecycle->disable('tenant-2', $connectionId)->reason);
        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $migration->migrate('tenant-2', $connectionId, [], [], [])->reason);
    }

    /**
     * The create endpoint makes a disabled connection from the preset and the
     * form, with the secret set and never shown, the preset's mapping, and the
     * administrator on the event it reports.
     *
     * @return void
     */
    public function testCreatesADisabledConnectionFromThePreset(): void
    {
        $reported = self::reported(ConnectionCreated::class);
        $result   = $this->create('google-client-secret');

        self::assertInstanceOf(ConnectionResult::class, $result);
        self::assertSame(ConnectionStatus::CREATED, $result->status);

        $summary = $result->connection;

        self::assertNotNull($summary);
        self::assertSame('oidc', $summary->protocol);
        self::assertSame('Acme Google Workspace', $summary->displayName);
        self::assertFalse($summary->enabled);
        self::assertSame('https://accounts.google.com', $summary->settings['issuer']);
        self::assertSame('https://openidconnect.googleapis.com/v1/userinfo', $summary->settings['userinfo_endpoint']);
        self::assertSame('1234.apps.googleusercontent.com', $summary->settings['client_id']);
        self::assertArrayNotHasKey('client_secret', $summary->settings);
        self::assertEquals(['client_secret' => MaskedSecret::set()], $summary->secrets);
        self::assertEquals([
            'email'        => 'email',
            'given_name'   => 'given_name',
            'family_name'  => 'family_name',
            'display_name' => 'name',
            'groups'       => 'groups',
        ], $summary->attributeMapping);

        self::assertCount(1, $reported);

        $event = $reported[0];

        self::assertInstanceOf(ConnectionCreated::class, $event);
        self::assertSame($this->user->getMorphClass(), $event->context()->actingIdentityMorphClass);
        self::assertSame('admin-1', $event->context()->actingIdentityId);
        $this->freshness->assertAsked(FreshnessOperation::CONNECTION_TRUST);
    }

    /**
     * A secret longer than 1024 bytes sends the form back with `too_long` under
     * `client_secret`, and creates nothing.
     *
     * @return void
     */
    public function testSendsAnInvalidFormBackWithItsViolations(): void
    {
        $response = $this->create(str_repeat('s', 1025));

        self::assertInstanceOf(RedirectResponse::class, $response);

        $errors = $response->getSession()?->get('errors');

        self::assertInstanceOf(ViewErrorBag::class, $errors);
        self::assertSame(['client_secret' => ['too_long']], $errors->getBag('default')->toArray());
        self::assertSame([], self::services()[0]->list($this->tenant->id));
    }

    /**
     * An update replaces a setting, removes another, renames the connection,
     * maps a custom target and removes a mapped one, keeping the secret it does
     * not name; a stale caller's trust change is refused and writes nothing.
     *
     * @return void
     */
    public function testUpdatesTheSettingsTheNameAndTheMapping(): void
    {
        [$connections] = self::services();

        $tenant       = $this->tenant;
        $actor        = $this->actor();
        $connectionId = $this->createdId();

        // @snippet-start connections-update
        $result = $connections->update($tenant->id, $connectionId, [
            'display_name'      => 'Acme SSO',
            'settings'          => ['token_endpoint' => 'https://idp.acme.example/oauth2/token', 'userinfo_endpoint' => null],
            'attribute_mapping' => ['department' => 'dept', 'groups' => null],
        ], $actor);
        // @snippet-end connections-update
        self::assertSame(ConnectionStatus::UPDATED, $result->status);
        self::assertSame(['token_endpoint', 'userinfo_endpoint', 'display_name', 'attribute_mapping'], $result->changedSettings);

        $summary = $result->connection;

        self::assertNotNull($summary);
        self::assertSame('Acme SSO', $summary->displayName);
        self::assertSame('https://idp.acme.example/oauth2/token', $summary->settings['token_endpoint']);
        self::assertArrayNotHasKey('userinfo_endpoint', $summary->settings);
        self::assertSame('dept', $summary->attributeMapping['department']);
        self::assertArrayNotHasKey('groups', $summary->attributeMapping);
        self::assertEquals(['client_secret' => MaskedSecret::set()], $summary->secrets);

        $this->freshness->staleFor(FreshnessOperation::CONNECTION_TRUST);

        $stale = $connections->update($tenant->id, $connectionId, ['settings' => ['token_endpoint' => 'https://idp.acme.example/token']], $actor);

        self::assertSame(ConnectionStatus::REFUSED, $stale->status);
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $stale->reason);
        self::assertSame('https://idp.acme.example/oauth2/token', $connections->get($tenant->id, $connectionId)?->settings['token_endpoint']);
    }

    /**
     * A connection is read by its tenant alone, compared byte for byte, and the
     * tenant's are listed oldest first.
     *
     * @return void
     */
    public function testReadsAConnectionAndListsTheTenants(): void
    {
        [$connections] = self::services();

        $tenant = $this->tenant;
        $oldest = $this->createdId();

        $this->clock->advance(60);

        $connectionId = $this->createdId();

        // @snippet-start connections-read
        $summary = $connections->get($tenant->id, $connectionId); // null when the tenant has no such connection
        $all     = $connections->list($tenant->id);               // oldest first
        // @snippet-end connections-read
        self::assertSame($connectionId, $summary?->id);
        self::assertSame([$oldest, $connectionId], array_map(static fn (ConnectionSummary $connection): string => $connection->id, $all));
        self::assertSame('2026-11-01T09:30:00+00:00', $all[0]->createdAt->toIso8601String());
        self::assertSame('2026-11-01T09:31:00+00:00', $all[1]->createdAt->toIso8601String());
        self::assertNull($connections->get('tenant-2', $connectionId));
    }

    /**
     * Enabling asks freshness every time: it enables a disabled connection,
     * succeeds as `unchanged` for an enabled one, and is refused while the
     * caller is stale.
     *
     * @return void
     */
    public function testEnablesAConnection(): void
    {
        [$connections] = self::services();

        $tenant       = $this->tenant;
        $actor        = $this->actor();
        $connectionId = $this->createdId();

        // @snippet-start connections-enable
        $result = $connections->enable($tenant->id, $connectionId, $actor);
        // @snippet-end connections-enable
        self::assertSame(ConnectionStatus::ENABLED, $result->status);
        self::assertTrue($result->connection?->enabled);
        $this->freshness->assertAsked(FreshnessOperation::CONNECTION_ENABLE);
        self::assertSame(ConnectionStatus::UNCHANGED, $connections->enable($tenant->id, $connectionId, $actor)->status);

        $this->freshness->staleFor(FreshnessOperation::CONNECTION_ENABLE);

        $stale = $connections->enable($tenant->id, $connectionId, $actor);

        self::assertSame(ConnectionStatus::REFUSED, $stale->status);
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $stale->reason);
    }

    /**
     * Disabling turns the connection off, revokes every session established
     * through it and reports it; disabling it again succeeds as `unchanged`,
     * and revokes and reports nothing.
     *
     * @return void
     */
    public function testDisablesAConnectionAndRevokesItsSessions(): void
    {
        [, $lifecycle] = self::services();

        $tenant       = $this->tenant;
        $actor        = $this->actor();
        $connectionId = $this->makeOidcConnection(new FakeOpenIdProvider(clock: $this->clock));
        $reported     = self::reported(ConnectionDisabled::class);

        // @snippet-start connections-disable
        $result = $lifecycle->disable($tenant->id, $connectionId, $actor);
        // @snippet-end connections-disable
        self::assertSame(ConnectionStatus::DISABLED, $result->status);
        self::assertFalse($result->connection?->enabled);
        $this->freshness->assertAsked(FreshnessOperation::CONNECTION_DISABLE);
        self::assertSame([[RevocationScopeKind::CONNECTION, RevocationReason::CONNECTION_DISABLED, $connectionId]], self::scopes($this->revocations));
        self::assertCount(1, $reported);

        $event = $reported[0];

        self::assertInstanceOf(ConnectionDisabled::class, $event);
        self::assertSame('admin-1', $event->context()->actingIdentityId);

        self::assertSame(ConnectionStatus::UNCHANGED, $lifecycle->disable($tenant->id, $connectionId, $actor)->status);
        self::assertCount(1, $this->revocations->revoked());
        self::assertCount(1, $reported);
    }

    /**
     * Deleting removes the connection for good, revokes every session
     * established through it and reports it once; a stale caller's deletion is
     * refused and leaves the connection.
     *
     * @return void
     */
    public function testDeletesAConnection(): void
    {
        [$connections, $lifecycle] = self::services();

        $tenant       = $this->tenant;
        $actor        = $this->actor();
        $kept         = $this->makeOidcConnection(new FakeOpenIdProvider(clock: $this->clock));
        $connectionId = $this->createdId();
        $reported     = self::reported(ConnectionDeleted::class);

        // @snippet-start connections-delete
        $result = $lifecycle->delete($tenant->id, $connectionId, $actor);
        // @snippet-end connections-delete
        self::assertSame(ConnectionStatus::DELETED, $result->status);
        self::assertNull($result->connection);
        self::assertNull($connections->get($tenant->id, $connectionId));
        $this->freshness->assertAsked(FreshnessOperation::CONNECTION_DELETE);
        self::assertSame([[RevocationScopeKind::CONNECTION, RevocationReason::CONNECTION_DELETED, $connectionId]], self::scopes($this->revocations));
        self::assertCount(1, $reported);

        $this->freshness->staleFor(FreshnessOperation::CONNECTION_DELETE);

        $stale = $lifecycle->delete($tenant->id, $kept, $actor);

        self::assertSame(ConnectionStatus::REFUSED, $stale->status);
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $stale->reason);
        self::assertNotNull($connections->get($tenant->id, $kept));
    }

    /**
     * A migration to a new issuer that leaves a link out is refused and changes
     * nothing; one that accounts for every link relinks two and removes two,
     * reports the change, each link removed and each relinked, and revokes the
     * removed links' sessions. The relinked person then signs in through their
     * new subject, and the leaver's old subject is unlinked.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testMigratesTheSubjectsOfTheLinks(): void
    {
        [, , $migration] = self::services();

        $tenant       = $this->tenant;
        $actor        = $this->actor();
        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);

        $linkId                 = $this->linkSubject($provider, $connectionId, 'subject-1', self::person(1));
        $otherLinkId            = $this->linkSubject($provider, $connectionId, 'subject-2', self::person(2));
        $leaverLinkId           = $this->linkSubject($provider, $connectionId, 'subject-3', self::person(3));
        $formerContractorLinkId = $this->linkSubject($provider, $connectionId, 'subject-4', self::person(4));

        $reported    = self::reported(ConnectionUpdated::class, LinkRemoved::class, LinkCreated::class);
        $unaccounted = $migration->migrate($tenant->id, $connectionId, ['settings' => ['issuer' => self::NEW_ISSUER]], [
            $linkId => ['00u1a2b3c4', null, self::NEW_ISSUER],
        ], [$leaverLinkId, $formerContractorLinkId], $actor);

        self::assertSame(ConnectionStatus::REFUSED, $unaccounted->status);
        self::assertSame(FailureReason::LINKS_UNACCOUNTED, $unaccounted->reason);
        self::assertCount(0, $reported);

        // @snippet-start connections-migrate
        $issuer = 'https://login.acme.example';

        $result = $migration->migrate($tenant->id, $connectionId, ['settings' => ['issuer' => $issuer]], [
            $linkId      => ['00u1a2b3c4', null, $issuer], // the new subject, no NameID format, the new issuer
            $otherLinkId => ['E-1042', null, $issuer],
        ], [$leaverLinkId, $formerContractorLinkId], $actor); // the links to remove
        // @snippet-end connections-migrate
        self::assertSame(ConnectionStatus::MIGRATED, $result->status);
        self::assertSame(['issuer'], $result->changedSettings);
        self::assertSame(self::NEW_ISSUER, $result->connection?->settings['issuer']);
        $this->freshness->assertAsked(FreshnessOperation::LINK_REMOVE);

        $removed  = array_fill(0, 4, LinkRemoved::class);
        $relinked = array_fill(0, 2, LinkCreated::class);

        self::assertSame([ConnectionUpdated::class, ...$removed, ...$relinked], array_map(get_class(...), $reported->getArrayCopy()));
        self::assertSame([LinkOrigin::MIGRATION, LinkOrigin::MIGRATION], array_map(
            static fn (SsoEvent $event): ?LinkOrigin => $event instanceof LinkCreated ? $event->origin : null,
            array_slice($reported->getArrayCopy(), 5),
        ));

        $revokedFor = array_map(static fn (RevocationScope $scope): ?string => $scope->identity?->id, $this->revocations->revoked());

        self::assertEqualsCanonicalizing(['person-3', 'person-4'], $revokedFor);

        $start    = $this->startFlow(Purpose::SIGN_IN, $connectionId);
        $signedIn = $this->admitSignIn($connectionId, $this->assertedAt($provider, $connectionId, $start, '00u1a2b3c4'), $start, 'session-1');

        self::assertTrue($signedIn->isAdmitted());
        self::assertEquals(self::person(1), $signedIn->linkedIdentity);

        $leaver = $this->startFlow(Purpose::SIGN_IN, $connectionId);

        self::assertSame(FailureReason::UNLINKED->value, $this->assertedAt($provider, $connectionId, $leaver, 'subject-3')->error);
    }

    /**
     * The services, as the guide resolves them for a request.
     *
     * @return array{
     *     0: \SineMacula\Laravel\Sso\Connections\ConnectionService,
     *     1: \SineMacula\Laravel\Sso\Connections\ConnectionLifecycle,
     *     2: \SineMacula\Laravel\Sso\Connections\SubjectMigration,
     * }
     */
    private static function services(): array
    {
        $services = require __DIR__ . '/admin/services.php';

        self::assertIsArray($services);
        self::assertCount(3, $services);

        [$connections, $lifecycle, $migration] = array_values($services);

        self::assertInstanceOf(ConnectionService::class, $connections);
        self::assertInstanceOf(ConnectionLifecycle::class, $lifecycle);
        self::assertInstanceOf(SubjectMigration::class, $migration);

        return [$connections, $lifecycle, $migration];
    }

    /**
     * Post the create form, with the client secret given, to the create
     * endpoint as the administrator, and answer what it answers.
     *
     * @param  string  $secret
     * @return mixed
     */
    private function create(string $secret): mixed
    {
        return self::atEndpoint([
            'connections' => self::services()[0],
            'tenant'      => $this->tenant,
            'user'        => $this->user,
            'request'     => Request::create('/admin/connections', 'POST', ['client_secret' => $secret]),
        ]);
    }

    /**
     * The create endpoint, given its input.
     *
     * @param  EndpointInput  $input
     * @return mixed
     */
    private static function atEndpoint(array $input): mixed
    {
        return require __DIR__ . '/admin/create.php';
    }

    /**
     * The id of a connection the create endpoint made.
     *
     * @return string
     */
    private function createdId(): string
    {
        $created = $this->create('google-client-secret');

        self::assertInstanceOf(ConnectionResult::class, $created);
        self::assertNotNull($created->connection);

        return $created->connection->id;
    }

    /**
     * The administrator, as the acting identity of each change.
     *
     * @return \SineMacula\Laravel\Sso\Administration\ActingIdentity
     */
    private function actor(): ActingIdentity
    {
        return new ActingIdentity($this->user->getMorphClass(), (string) $this->user->getKey());
    }

    /**
     * Link the person through a whole `link` flow, the provider asserting the
     * subject given, and answer the link's id.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @param  string  $connectionId
     * @param  string  $subject
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $person
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function linkSubject(FakeOpenIdProvider $provider, string $connectionId, string $subject, IdentityReference $person): string
    {
        $start    = $this->startFlow(Purpose::LINK, $connectionId, $person);
        $asserted = static fn (FakeIdToken $token): FakeIdToken => $token->with('sub', $subject);
        $linked   = $this->redeemLink($connectionId, $this->respondAtProvider($provider, $connectionId, $start, $asserted), $start, $person);

        self::assertTrue($linked->isRedeemed());
        self::assertNotNull($linked->linkId);

        return $linked->linkId;
    }

    /**
     * Have the provider answer the start under the new issuer, in the ID
     * token's `iss` and the callback's RFC 9207 `iss` alike, asserting the
     * subject given, and read the redirect the browser comes back with.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  string  $subject
     * @return \SineMacula\Laravel\Sso\Testing\HandoffRedirect
     *
     * @throws \Random\RandomException
     */
    private function assertedAt(FakeOpenIdProvider $provider, string $connectionId, StartResult $start, string $subject): HandoffRedirect
    {
        $asserted = static fn (FakeIdToken $token): FakeIdToken => $token->with('iss', self::NEW_ISSUER)->with('sub', $subject);
        $grant    = $provider->authorize($start, $asserted);
        $result   = app(CompletionService::class)->callback($connectionId, new CompletionRequest('GET', $grant->query(['iss' => self::NEW_ISSUER]), []));

        return HandoffRedirect::from(app(CompletionResponses::class)->from($result, 'GET'));
    }

    /**
     * Each scope revoked, as its kind, its reason and its connection.
     *
     * @param  \Tests\Integration\Examples\ManagingConnections\RevokedSessions  $revocations
     * @return list<array{0: \SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind, 1: \SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason, 2: ?string}>
     */
    private static function scopes(RevokedSessions $revocations): array
    {
        return array_map(static fn (RevocationScope $scope): array => [$scope->kind, $scope->reason, $scope->connectionId], $revocations->revoked());
    }

    /**
     * The person, as the application names them to the package.
     *
     * @param  int  $number
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    private static function person(int $number): IdentityReference
    {
        return new IdentityReference('user', "person-{$number}");
    }

    /**
     * The events of the classes given the package reports from now on, as they
     * are dispatched.
     *
     * @param  class-string<\SineMacula\Laravel\Sso\Contracts\SsoEvent>  ...$events
     * @return \ArrayObject<int, \SineMacula\Laravel\Sso\Contracts\SsoEvent>
     */
    private static function reported(string ...$events): \ArrayObject
    {
        /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Contracts\SsoEvent> $reported */
        $reported = new \ArrayObject;

        Event::listen($events, static function (SsoEvent $event) use ($reported): void {
            $reported->append($event);
        });

        return $reported;
    }
}
