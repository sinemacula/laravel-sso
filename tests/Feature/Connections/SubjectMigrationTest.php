<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Connections\SubjectMigration;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\LinkRemoved;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesEnforcement;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Enforcement\RecordingRevocation;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\TestCase;

/**
 * Feature tests for the explicit subject migration (SSO-2.13, SSO-2.12,
 * SSO-4.5, SSO-8.4): a change to what subjects mean made with each link
 * relinked to its new subject or removed; the relinks validated with the
 * change, each refused at `relinks.<id>`; a new subject that collides, or an
 * identity at its link limit, rolling everything back; the freshness asked
 * (`sso.connection.trust` and `sso.link.remove`, through `checkAll()`); the
 * sessions of each identity whose link was removed revoked; what is in flight
 * voided; and the events, after commit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectMigration::class)]
#[CoversClass(ConnectionService::class)]
#[CoversClass(ConnectionResult::class)]
final class SubjectMigrationTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesEnforcement, UsesFlowTables;

    /** @var string The tenant the connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var string The issuer the connection trusts, and its links were made with. */
    private const string ISSUER = 'https://idp.example.com';

    /** @var string The issuer the migration moves the connection to. */
    private const string NEW_ISSUER = 'https://login.example.com';

    /** @var array<string, string> The settings of a complete OIDC connection. */
    private const array OIDC = [
        'issuer'                 => self::ISSUER,
        'authorization_endpoint' => 'https://idp.example.com/authorize',
        'token_endpoint'         => 'https://idp.example.com/token',
        'jwks_uri'               => 'https://idp.example.com/jwks',
        'client_id'              => 'client-123',
    ];

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract the helper asks. */
    private RecordingFreshness $freshness;

    /** @var \Tests\Fixtures\Enforcement\RecordingRevocation The revocation contract the helper calls. */
    private RecordingRevocation $revocation;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The tenant's OIDC connection. */
    private Connection $connection;

    /** @var array<string, \SineMacula\Laravel\Sso\Models\Link> The connection's links, by name, each of its own identity. */
    private array $links = [];

    /**
     * Bind a fixed clock, a recording freshness contract and revocation, create
     * the tables, an OIDC connection with three links, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock      = new FixedClock('2026-11-01T09:30:00Z');
        $this->freshness  = new RecordingFreshness;
        $this->revocation = new RecordingRevocation;

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Freshness::class, $this->freshness);
        $this->app?->instance(SessionRevocation::class, $this->revocation);

        config()->set('sso.features.oidc', true);

        $this->createConnectionTables();
        $this->createEnforcementTable();
        $this->createFlowTables();

        $created = $this->connections()->create(self::TENANT, 'oidc', 'Acme', self::OIDC);

        $this->connection = Connection::query()->whereKey((string) $created->connection?->id)->sole();

        foreach (['first' => '1', 'second' => '2', 'third' => '3'] as $name => $identity) {
            $this->links[$name] = $this->makeLink($this->connection, $name . '-subject', ['identity_id' => $identity]);
        }

        $this->freshness->reset();
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
        $this->dropFlowTables();
        $this->dropEnforcementTable();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * The change is made; each link relinked is replaced by a link of its
     * identity to the new subject, the issuer the one given or the link's own;
     * every other link is removed and its identity's sessions revoked; what is
     * in flight is voided; and the change, each removal and each new link are
     * reported once it commits, in that order.
     *
     * @return void
     */
    public function testRelinksAndRemovesTheLinks(): void
    {
        $request = $this->makeAuthorizationRequest($this->connection);
        $code    = $this->makeHandoffCode($this->connection);
        $actor   = new ActingIdentity('App\Models\User', '42');

        $result = $this->migration()->migrate(self::TENANT, $this->connection->id, ['settings' => ['issuer' => self::NEW_ISSUER]], [
            $this->links['second']->id => ['second-new', null, self::NEW_ISSUER],
            $this->links['first']->id  => ['first-new', 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'],
        ], $actor);

        $summary = $result->connection;

        self::assertSame(ConnectionStatus::MIGRATED, $result->status);
        self::assertTrue($result->isChanged());
        self::assertSame(['issuer'], $result->changedSettings);
        self::assertNotNull($summary);
        self::assertSame(self::NEW_ISSUER, $summary->settings['issuer']);
        self::assertSame(self::NEW_ISSUER, $this->reread()->settings['issuer']);
        self::assertSame([[FreshnessOperation::CONNECTION_TRUST, 300], [FreshnessOperation::LINK_REMOVE, 300]], $this->freshness->asked());

        self::assertSame([
            ['1', self::ISSUER, 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', 'first-new', 'active'],
            ['2', self::NEW_ISSUER, null, 'second-new', 'active'],
        ], self::linksNow());
        self::assertSame(0, Link::query()->whereKey(array_map(static fn (Link $link): string => $link->id, $this->links))->count());
        self::assertSame(
            (new LinkSubject(self::NEW_ISSUER, 'second-new'))->key(),
            Link::query()->where('identity_id', '2')->sole()->subject_key,
        );

        self::assertSame('2026-11-01T09:30:00+00:00', AuthorizationRequest::query()->findOrFail($request->id)->voided_at?->toIso8601String());
        self::assertSame('2026-11-01T09:30:00+00:00', HandoffCode::query()->findOrFail($code->id)->voided_at?->toIso8601String());

        $this->assertRevokedIdentities(['3']);
        $this->assertEventSequence([ConnectionUpdated::class, LinkRemoved::class, LinkRemoved::class, LinkRemoved::class, LinkCreated::class, LinkCreated::class]);

        $events = $this->recordedEvents();

        self::assertInstanceOf(ConnectionUpdated::class, $events[0]);
        self::assertSame(['issuer'], $events[0]->changedSettings);
        self::assertSame(['1', '2', '3', '2', '1'], array_map(static fn (SsoEvent $event): ?string => $event->context()->identityId, array_slice($events, 1)));

        foreach (array_slice($events, 4) as $event) {
            self::assertInstanceOf(LinkCreated::class, $event);
            self::assertSame(LinkOrigin::MIGRATION, $event->origin);
        }

        foreach ($events as $event) {
            self::assertSame($this->connection->id, $event->context()->connectionId);
            self::assertSame('42', $event->context()->actingIdentityId);
        }
    }

    /**
     * With no relink, every link of the connection is removed and every
     * identity's sessions through it revoked.
     *
     * @return void
     */
    public function testRemovesEveryLinkNotRelinked(): void
    {
        $result = $this->migration()->migrate(self::TENANT, $this->connection->id, ['settings' => ['client_id' => 'client-456']], []);

        self::assertSame(ConnectionStatus::MIGRATED, $result->status);
        self::assertSame(['client_id'], $result->changedSettings);
        self::assertSame([], self::linksNow());
        $this->assertRevokedIdentities(['1', '2', '3']);
        $this->assertEventSequence([ConnectionUpdated::class, LinkRemoved::class, LinkRemoved::class, LinkRemoved::class]);
    }

    /**
     * A migration that changes no setting of trust still asks
     * `sso.connection.trust` and `sso.link.remove`, and voids what is in
     * flight.
     *
     * @return void
     */
    public function testAMigrationAlwaysAsksTrustAndRemoval(): void
    {
        $request = $this->makeAuthorizationRequest($this->connection);

        $result = $this->migration()->migrate(self::TENANT, $this->connection->id, ['display_name' => 'Renamed'], [$this->links['first']->id => ['first-subject']]);

        self::assertSame(ConnectionStatus::MIGRATED, $result->status);
        self::assertSame(['display_name'], $result->changedSettings);
        self::assertSame([[FreshnessOperation::CONNECTION_TRUST, 300], [FreshnessOperation::LINK_REMOVE, 300]], $this->freshness->asked());
        self::assertNotNull(AuthorizationRequest::query()->findOrFail($request->id)->voided_at);
    }

    /**
     * Rows of `[operation]`: each operation a migration asks, stale alone.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation}>
     */
    public static function provideMigrationOperations(): iterable
    {
        yield from [
            'trust'       => [FreshnessOperation::CONNECTION_TRUST],
            'link remove' => [FreshnessOperation::LINK_REMOVE],
        ];
    }

    /**
     * A caller who is not fresh enough for either operation is refused with
     * `freshness_required`, even for a change that asks neither, and nothing is
     * written, removed, revoked or reported.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @return void
     */
    #[DataProvider('provideMigrationOperations')]
    public function testRefusesACallerStaleForEitherOperation(FreshnessOperation $operation): void
    {
        $this->app?->instance(Freshness::class, FakeFreshness::fresh()->staleFor($operation));

        $result = $this->migration()->migrate(self::TENANT, $this->connection->id, ['display_name' => 'Renamed'], []);

        self::assertSame(ConnectionStatus::REFUSED, $result->status);
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        $this->assertNothingChanged();
    }

    /**
     * A stale caller is refused at the first operation, and nothing changes.
     *
     * @return void
     */
    public function testRefusesAStaleCaller(): void
    {
        $this->freshness->answer(FreshnessOutcome::STALE);

        $result = $this->migration()->migrate(self::TENANT, $this->connection->id, ['settings' => ['issuer' => self::NEW_ISSUER]], []);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertSame([[FreshnessOperation::CONNECTION_TRUST, 300]], $this->freshness->asked());
        $this->assertNothingChanged();
    }

    /**
     * Rows of `[relink, code]`: each relink of the wrong shape, and its code.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideMalformedRelinks(): iterable
    {
        yield from [
            'a string'               => ['subject', 'invalid_type'],
            'a map'                  => [['subject' => 'subject'], 'invalid_type'],
            'an empty list'          => [[], 'invalid_type'],
            'four parts'             => [['subject', null, null, 'extra'], 'invalid_type'],
            'no subject'             => [[null], 'invalid_type'],
            'a subject of a number'  => [[5], 'invalid_type'],
            'a format of a number'   => [['subject', 5], 'invalid_type'],
            'an issuer of a boolean' => [['subject', null, true], 'invalid_type'],
            'an empty subject'       => [[''], 'invalid_format'],
            'an overlong subject'    => [[str_repeat('s', 1025)], 'invalid_format'],
            'an empty format'        => [['subject', ''], 'invalid_format'],
            'an overlong format'     => [['subject', str_repeat('f', 256)], 'invalid_format'],
            'an empty issuer'        => [['subject', null, ''], 'invalid_format'],
            'an overlong issuer'     => [['subject', null, str_repeat('i', 1025)], 'invalid_format'],
        ];
    }

    /**
     * A relink of the wrong shape is refused at `relinks.<id>`, and nothing is
     * asked, written, removed or reported.
     *
     * @param  mixed  $relink
     * @param  string  $code
     * @return void
     */
    #[DataProvider('provideMalformedRelinks')]
    public function testRefusesAMalformedRelink(mixed $relink, string $code): void
    {
        $id     = $this->links['first']->id;
        $result = $this->migration()->migrate(self::TENANT, $this->connection->id, ['settings' => ['issuer' => self::NEW_ISSUER]], [$id => $relink]);

        self::assertSame(ConnectionStatus::INVALID, $result->status);
        self::assertSame(FailureReason::SETTINGS_INVALID, $result->reason);
        self::assertSame([['relinks.' . $id, $code]], self::violationsOf($result));
        self::assertSame([], $this->freshness->asked());
        $this->assertNothingChanged();
    }

    /**
     * Rows of `[relink]`: each well-shaped relink, at the bounds.
     *
     * @return iterable<string, array{0: list<?string>}>
     */
    public static function provideWellShapedRelinks(): iterable
    {
        yield from [
            'the subject alone'        => [['s']],
            'the longest subject'      => [[str_repeat('s', 1024)]],
            'a null format'            => [['subject', null]],
            'the longest format'       => [['subject', str_repeat('f', 255)]],
            'three parts'              => [['subject', 'format', 'https://idp.example.com/other']],
            'a null format and issuer' => [['subject', null, null]],
            'the longest issuer'       => [['subject', null, str_repeat('i', 1024)]],
        ];
    }

    /**
     * A relink of one to three parts within a link's bounds is accepted.
     *
     * @param  list<?string>  $relink
     * @return void
     */
    #[DataProvider('provideWellShapedRelinks')]
    public function testAcceptsAWellShapedRelink(array $relink): void
    {
        $result = $this->migration()->migrate(self::TENANT, $this->connection->id, ['settings' => ['issuer' => self::NEW_ISSUER]], [$this->links['first']->id => $relink]);

        self::assertSame(ConnectionStatus::MIGRATED, $result->status);

        $link = Link::query()->where('identity_id', '1')->sole();

        self::assertSame($relink[0], $link->subject);
        self::assertSame($relink[1] ?? null, $link->name_id_format);
        self::assertSame($relink[2] ?? self::ISSUER, $link->issuer);
    }

    /**
     * An id that is not one of the connection's links is `unknown`, another
     * connection's link included; a reserved link is `not_allowed`; each is
     * reported after the change's own violations, in the order given, and
     * nothing is asked, written or reported.
     *
     * @return void
     */
    public function testRefusesAnUnknownOrReservedLink(): void
    {
        $other    = $this->makeConnection();
        $theirs   = $this->makeLink($other, 'their-subject');
        $reserved = $this->makeLink($this->connection, 'reserved-subject', [
            'identity_id'            => '4',
            'state'                  => LinkState::RESERVED,
            'reservation_expires_at' => $this->clock->now()->addMinute(),
            'reservation_reference'  => str_repeat('r', 32),
        ]);

        $result = $this->migration()->migrate(self::TENANT, $this->connection->id, ['settings' => ['issuer' => 'http://login.example.com']], [
            '01jbunknownlink00000000000' => ['subject'],
            $theirs->id                  => ['subject'],
            $reserved->id                => ['subject'],
            $this->links['first']->id    => ['first-new'],
        ]);

        self::assertSame(ConnectionStatus::INVALID, $result->status);
        self::assertSame([
            ['issuer', 'not_https'],
            ['relinks.01jbunknownlink00000000000', 'unknown'],
            ['relinks.' . $theirs->id, 'unknown'],
            ['relinks.' . $reserved->id, 'not_allowed'],
        ], self::violationsOf($result));
        self::assertSame([], $this->freshness->asked());
        self::assertSame(4, Link::query()->where('connection_id', $this->connection->id)->count());
        $this->assertNoEvents();
    }

    /**
     * Two relinks to the same new subject collide: the second is `duplicate` at
     * its id, and everything is rolled back, the change, the removals and the
     * voiding included, with nothing reported.
     *
     * @return void
     */
    public function testACollisionRollsEverythingBack(): void
    {
        $request = $this->makeAuthorizationRequest($this->connection);

        $result = $this->migration()->migrate(self::TENANT, $this->connection->id, ['settings' => ['issuer' => self::NEW_ISSUER]], [
            $this->links['first']->id  => ['the-same-subject'],
            $this->links['second']->id => ['the-same-subject'],
        ]);

        self::assertSame(ConnectionStatus::INVALID, $result->status);
        self::assertSame([['relinks.' . $this->links['second']->id, 'duplicate']], self::violationsOf($result));
        self::assertNull(AuthorizationRequest::query()->findOrFail($request->id)->voided_at);
        $this->assertNothingChanged(false);
    }

    /**
     * An identity relinked twice in a connection that allows it one link
     * reaches its limit: the second is `too_many` at its id, and everything is
     * rolled back.
     *
     * @return void
     */
    public function testAnIdentityAtItsLinkLimitRollsEverythingBack(): void
    {
        $twin = $this->makeLink($this->connection, 'twin-subject', ['identity_id' => '1']);

        $result = $this->migration()->migrate(self::TENANT, $this->connection->id, ['settings' => ['issuer' => self::NEW_ISSUER]], [
            $this->links['first']->id => ['first-new'],
            $twin->id                 => ['twin-new'],
        ]);

        self::assertSame([['relinks.' . $twin->id, 'too_many']], self::violationsOf($result));
        self::assertSame(self::ISSUER, $this->reread()->settings['issuer']);
        self::assertSame(4, Link::query()->where('connection_id', $this->connection->id)->count());
        $this->assertNoEvents();
    }

    /**
     * A change that changes nothing is `unchanged`: no link is relinked or
     * removed, and nothing is asked or reported.
     *
     * @return void
     */
    public function testAChangeOfNothingTouchesNoLink(): void
    {
        $result = $this->migration()->migrate(self::TENANT, $this->connection->id, ['settings' => ['issuer' => self::ISSUER]], [$this->links['first']->id => ['first-new']]);

        self::assertSame(ConnectionStatus::UNCHANGED, $result->status);
        self::assertSame($this->connection->id, $result->connection?->id);
        self::assertSame([], $this->freshness->asked());
        $this->assertNothingChanged();
    }

    /**
     * Another tenant's connection is not found, and a connection whose protocol
     * is unavailable is refused, with nothing changed.
     *
     * @return void
     */
    public function testRefusesWhatItCannotFindOrUse(): void
    {
        $retired = $this->makeConnection(['protocol' => 'retired']);

        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $this->migration()->migrate('tenant-2', $this->connection->id, ['display_name' => 'Renamed'], [])->reason);
        self::assertSame(FailureReason::PROTOCOL_UNAVAILABLE, $this->migration()->migrate(self::TENANT, $retired->id, ['display_name' => 'Renamed'], [])->reason);
        $this->assertNothingChanged();
    }

    /**
     * An empty tenant id is the application's mistake, and leaves no
     * transaction open.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAMalformedTenantId(): void
    {
        try {
            $this->migration()->migrate('', $this->connection->id, [], []);
            self::fail('An empty tenant id was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A tenant id is 1 to 255 bytes.', $exception->getMessage());
        }

        self::assertSame(0, $this->connection->getConnection()->transactionLevel());
    }

    /**
     * Assert the connection, its links and their identities' sessions are as
     * they were, and nothing was reported.
     *
     * @param  bool  $unrevoked
     * @return void
     */
    private function assertNothingChanged(bool $unrevoked = true): void
    {
        self::assertSame(self::ISSUER, $this->reread()->settings['issuer']);
        self::assertSame('Acme', $this->reread()->display_name);
        self::assertSame(
            array_map(static fn (Link $link): string => $link->id, array_values($this->links)),
            Link::query()->where('connection_id', $this->connection->id)->orderBy('id')->pluck('id')->all(),
        );
        self::assertSame(0, $this->connection->getConnection()->transactionLevel());
        $this->assertNoEvents();

        if (!$unrevoked) {
            return;
        }

        self::assertSame([], $this->revocation->calls());
    }

    /**
     * Assert the sessions of exactly these identities, in order, were revoked
     * through the connection, each inside the transaction.
     *
     * @param  list<string>  $identities
     * @return void
     */
    private function assertRevokedIdentities(array $identities): void
    {
        $calls = $this->revocation->calls();

        self::assertCount(count($identities), $calls);

        foreach ($calls as $index => $call) {

            $scope = $call['scope'];

            self::assertInstanceOf(RevocationScope::class, $scope);
            self::assertSame(RevocationScopeKind::IDENTITY_CONNECTION, $scope->kind);
            self::assertSame(RevocationReason::LINK_REMOVED, $scope->reason);
            self::assertSame(self::TENANT, $scope->tenantId);
            self::assertSame($this->connection->id, $scope->connectionId);
            self::assertTrue((new IdentityReference('user', $identities[$index]))->is($scope->identity ?? new IdentityReference('none', '0')));
            self::assertGreaterThan(0, $call['level']);
        }
    }

    /**
     * The connection, read again.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function reread(): Connection
    {
        return Connection::query()->whereKey($this->connection->id)->sole();
    }

    /**
     * The subject migration helper, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Connections\SubjectMigration
     */
    private function migration(): SubjectMigration
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(SubjectMigration::class);
    }

    /**
     * The management helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionService
     */
    private function connections(): ConnectionService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ConnectionService::class);
    }

    /**
     * Each link of every connection as `[identity id, issuer, format, subject,
     * state]`, by identity id.
     *
     * @return list<array{0: string, 1: string, 2: ?string, 3: string, 4: string}>
     */
    private static function linksNow(): array
    {
        $links = Link::query()->orderBy('identity_id')->get()->all();

        return array_values(array_map(static fn (Link $link): array => [$link->identity_id, $link->issuer, $link->name_id_format, $link->subject, $link->state->value], $links));
    }

    /**
     * Each violation of the result as `[setting, code]`.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionResult  $result
     * @return list<array{0: string, 1: string}>
     */
    private static function violationsOf(ConnectionResult $result): array
    {
        return array_map(static fn (SettingViolation $violation): array => [$violation->setting, $violation->code->value], $result->violations);
    }
}
