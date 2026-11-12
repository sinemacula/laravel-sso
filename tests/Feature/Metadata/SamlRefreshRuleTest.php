<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\MetadataExpiry;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\SamlRefreshRule;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for when a SAML connection follows its metadata URL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SamlRefreshRule::class)]
final class SamlRefreshRuleTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The tenant whose connection refreshes. */
    private const string TENANT = 'tenant-1';

    /** @var string The URL the provider serves its metadata at. */
    private const string URL = 'https://idp.example.test/metadata.xml';

    /** @var string The stale limit past when each test starts. */
    private const string LIMIT = '2026-12-01T09:30:00+00:00';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher a refresh fetches through. */
    private FakeFetcher $fetcher;

    /**
     * Bind a fixed clock, a fetcher serving anchor-signed metadata and fresh
     * freshness, enable SAML and refresh, and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock   = new FixedClock('2026-11-01T09:30:00Z');
        $this->fetcher = new FakeFetcher;

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Fetcher::class, $this->fetcher);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.metadata_refresh', true);
        config()->set('sso.endpoints.base_url', 'https://api.example.com');

        $this->usePackageTables();

        $this->serve(self::metadata()->with(['aggregate' => ['https://other.example.test/saml'], 'sign' => 'aggregate']));
    }

    /**
     * Rows of `[anchored, switch, due]` for a connection with a URL.
     *
     * @return iterable<string, array{0: bool, 1: ?bool, 2: bool}>
     */
    public static function provideSchedule(): iterable
    {
        yield from [
            'an anchor, unset' => [true, null, true],
            'an anchor, true'  => [true, true, true],
            'an anchor, false' => [true, false, false],
            'no anchor, unset' => [false, null, false],
            'no anchor, true'  => [false, true, true],
            'no anchor, false' => [false, false, false],
        ];
    }

    /**
     * The schedule and queued refresh follow the anchor and switch.
     *
     * @param  bool  $anchored
     * @param  ?bool  $switch
     * @param  bool  $due
     * @return void
     */
    #[DataProvider('provideSchedule')]
    public function testTheScheduleFollowsTheAnchorAndTheSwitch(bool $anchored, ?bool $switch, bool $due): void
    {
        $connection = $this->saml(['metadata_refresh' => $switch]);

        if ($anchored) {
            $this->anchor($connection, self::idp()->certificate());
        }

        self::assertSame($due ? [$connection->id] : [], $this->refresher()->dueConnectionIds());
        self::assertSame($due ? RefreshOutcome::REFRESHED : RefreshOutcome::SKIPPED, $this->refresher()->refreshQueued($connection->id, Clients::browser())->outcome);
        self::assertSame($due ? 1 : 0, $this->row($connection)->metadata_version);
        self::assertCount($due ? 1 : 0, $this->fetcher->requests());
    }

    /**
     * Every chunk of a due listing keeps its order whatever anchors bring in.
     *
     * @return void
     */
    public function testAListingKeepsItsOrderAcrossAnchorsAndSwitches(): void
    {
        $first  = $this->saml(['metadata_refresh' => true], ['id' => '01jb0000000000000000000001']);
        $second = $this->saml([], ['id' => '01jb0000000000000000000002']);
        $third  = $this->saml([], ['id' => '01jb0000000000000000000003']);
        $fourth = $this->saml(['metadata_refresh' => false], ['id' => '01jb0000000000000000000004']);

        $this->anchor($third, self::idp()->certificate());
        $this->anchor($fourth, self::idp()->certificate());

        self::assertSame([$first->id, $third->id], $this->refresher()->dueConnectionIds());
        self::assertSame(0, $this->row($second)->metadata_version);
    }

    /**
     * Adding the first anchor makes the connection due at once with no clock
     * running until its first refresh.
     *
     * @return void
     */
    public function testAddingAnAnchorTurnsTheDefaultOn(): void
    {
        $connection = $this->saml([], [
            'metadata_fetched_at'  => $this->clock->now()->subDays(40),
            'metadata_valid_until' => $this->clock->now()->subDay(),
            'metadata_refresh_at'  => $this->clock->now()->addDay(),
        ]);

        self::assertSame([], $this->refresher()->dueConnectionIds());
        self::assertNull($this->expiry()->expiresAt($this->row($connection)));

        $this->anchor($connection, self::idp()->certificate());

        $row = $this->row($connection);

        self::assertSame([null, null, null], [$row->metadata_fetched_at, $row->metadata_valid_until, $row->metadata_refresh_at]);
        self::assertSame(1, $row->trust_version);
        self::assertNull($this->expiry()->expiresAt($row));
        self::assertSame([$connection->id], $this->refresher()->dueConnectionIds());

        self::assertTrue($this->refresher()->refreshQueued($connection->id, Clients::browser())->isRefreshed());
        self::assertSame(self::LIMIT, $this->expiry()->expiresAt($this->row($connection))?->toIso8601String());
    }

    /**
     * Removing the last anchor stops refresh, and old stamps no longer expire
     * the connection.
     *
     * @return void
     */
    public function testRemovingAnAnchorStopsTheDefault(): void
    {
        $connection = $this->saml();
        $key        = $this->anchor($connection, self::idp()->certificate());

        $this->row($connection)->forceFill(['metadata_fetched_at' => $this->clock->now()->subDays(40), 'metadata_valid_until' => $this->clock->now()->subDay()])->save();

        self::assertTrue($this->expiry()->isExpired($this->row($connection)));
        self::assertSame([$connection->id], $this->refresher()->dueConnectionIds());

        self::assertTrue(app(KeyService::class)->distrustCertificate(self::TENANT, $connection->id, $key, Clients::browser())->isSucceeded());

        $row = $this->row($connection);

        self::assertSame(2, $row->trust_version);
        self::assertFalse($this->expiry()->isExpired($row));
        self::assertNull($this->expiry()->expiresAt($row));
        self::assertSame([], $this->refresher()->dueConnectionIds());
        self::assertSame(RefreshOutcome::SKIPPED, $this->refresher()->refreshQueued($connection->id, Clients::browser())->outcome);
    }

    /**
     * An anchor removed and added again does not revive an old stamp.
     *
     * @return void
     */
    public function testAnAnchorAddedAgainDoesNotReviveAnOldStamp(): void
    {
        $connection = $this->saml();
        $key        = $this->anchor($connection, self::idp()->certificate());

        $this->row($connection)->forceFill(['metadata_fetched_at' => $this->clock->now()->subDays(40)])->save();

        app(KeyService::class)->distrustCertificate(self::TENANT, $connection->id, $key, Clients::browser());

        self::assertFalse($this->expiry()->isExpired($this->row($connection)));

        $this->anchor($connection, self::idp()->certificate());

        self::assertFalse($this->expiry()->isExpired($this->row($connection)));
        self::assertNull($this->row($connection)->metadata_fetched_at);
    }

    /**
     * A second anchor, or removing one of two, changes nothing.
     *
     * @return void
     */
    public function testASecondAnchorChangesNothing(): void
    {
        $connection = $this->saml();

        $this->anchor($connection, self::idp()->certificate());

        $this->row($connection)->forceFill(['metadata_fetched_at' => $this->clock->now(), 'metadata_refresh_at' => $this->clock->now()->addDay()])->save();

        $second = $this->anchor($connection, Certificates::distinct(1));
        $row    = $this->row($connection);

        self::assertSame(self::LIMIT, $this->expiry()->expiresAt($row)?->toIso8601String());
        self::assertSame('2026-11-02T09:30:00+00:00', $row->metadata_refresh_at?->toIso8601String());

        app(KeyService::class)->distrustCertificate(self::TENANT, $connection->id, $second, Clients::browser());

        self::assertSame(self::LIMIT, $this->expiry()->expiresAt($this->row($connection))?->toIso8601String());
    }

    /**
     * An anchor clears only what it brings in: nothing if already `true` or
     * without a URL, the deadline alone if `false`.
     *
     * @return void
     */
    public function testAnAnchorClearsOnlyWhatItBringsIn(): void
    {
        $stamp   = ['metadata_fetched_at' => $this->clock->now()->subDays(1)];
        $optedIn = $this->saml(['metadata_refresh' => true], $stamp);
        $noUrl   = $this->saml(['metadata_url' => null], $stamp);
        $off     = $this->saml(['metadata_refresh' => false], $stamp);

        $this->anchor($optedIn, self::idp()->certificate());
        $this->anchor($noUrl, self::idp()->certificate());
        $this->anchor($off, self::idp()->certificate());

        self::assertSame('2026-10-31T09:30:00+00:00', $this->row($optedIn)->metadata_fetched_at?->toIso8601String());
        self::assertSame('2026-10-31T09:30:00+00:00', $this->row($noUrl)->metadata_fetched_at?->toIso8601String());
        self::assertNull($this->row($off)->metadata_fetched_at);
        self::assertNull($this->expiry()->expiresAt($this->row($off)));
        self::assertSame([$optedIn->id], $this->refresher()->dueConnectionIds());
    }

    /**
     * An explicit `false` on an anchored connection is off, but an
     * administrator's refresh still stamps and expires it.
     *
     * @return void
     */
    public function testFalseOnAnAnchoredConnectionIsOffAndKeepsTheFetchsDeadline(): void
    {
        $connection = $this->saml(['metadata_refresh' => false]);

        $this->anchor($connection, self::idp()->certificate());

        self::assertSame([], $this->refresher()->dueConnectionIds());
        self::assertTrue($this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor(), Clients::browser())->isRefreshed());
        self::assertSame(self::LIMIT, $this->expiry()->expiresAt($this->row($connection))?->toIso8601String());
        self::assertSame([], $this->refresher()->dueConnectionIds());

        $this->clock->advance(2592000);

        self::assertTrue($this->expiry()->isExpired($this->row($connection)));
        self::assertSame([], $this->refresher()->dueConnectionIds());
    }

    /**
     * Opting in with a stale authentication is refused and changes nothing.
     *
     * @return void
     */
    public function testOptingInRequiresFreshness(): void
    {
        $connection = $this->saml();
        $request    = $this->makeAuthorizationRequest($connection);
        $freshness  = FakeFreshness::stale();

        $this->app?->instance(Freshness::class, $freshness);

        $result = app(ConnectionService::class)->update(self::TENANT, $connection->id, ['settings' => ['metadata_refresh' => true]], Clients::browser());
        $row    = $this->row($connection);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertSame([FreshnessOperation::CONNECTION_TRUST], array_column($freshness->asked(), 'operation'));
        self::assertArrayNotHasKey('metadata_refresh', $row->settings);
        self::assertSame(0, $row->trust_version);
        self::assertNull($request->fresh()?->voided_at);
        self::assertSame([], $this->refresher()->dueConnectionIds());
    }

    /**
     * Opting in is a trust change that voids flights, is reported, makes the
     * connection due and starts no clock from an old stamp.
     *
     * @return void
     */
    public function testOptingInRaisesTheTrustVersionAndStartsCleanly(): void
    {
        $connection = $this->saml([], [
            'metadata_fetched_at'  => $this->clock->now()->subDays(40),
            'metadata_valid_until' => $this->clock->now()->subDay(),
            'metadata_refresh_at'  => $this->clock->now()->addDay(),
        ]);

        $request = $this->makeAuthorizationRequest($connection);

        $this->startRecordingEvents();

        $result = app(ConnectionService::class)->update(self::TENANT, $connection->id, ['settings' => ['metadata_refresh' => true]], Clients::browser());
        $row    = $this->row($connection);
        $events = $this->recordedEvents();

        self::assertSame(['metadata_refresh'], $result->changedSettings);
        self::assertSame(1, $row->trust_version);
        self::assertSame('2026-11-01T09:30:00+00:00', $request->fresh()?->voided_at?->toIso8601String());
        self::assertCount(1, $events);
        self::assertInstanceOf(ConnectionUpdated::class, $events[0]);
        self::assertSame(['metadata_refresh'], $events[0]->changedSettings);
        self::assertSame([null, null, null], [$row->metadata_fetched_at, $row->metadata_valid_until, $row->metadata_refresh_at]);
        self::assertFalse($this->expiry()->isExpired($row));
        self::assertSame([$connection->id], $this->refresher()->dueConnectionIds());
    }

    /**
     * Rows of `[stored, given]` switch changes, each a trust change.
     *
     * @return iterable<string, array{0: ?bool, 1: ?bool}>
     */
    public static function provideSwitchChanges(): iterable
    {
        yield from [
            'unset to false' => [null, false],
            'true to false'  => [true, false],
            'true to unset'  => [true, null],
            'false to true'  => [false, true],
            'false to unset' => [false, null],
        ];
    }

    /**
     * Every switch change asks the connection's trust and raises its trust
     * version.
     *
     * @param  ?bool  $stored
     * @param  ?bool  $given
     * @return void
     */
    #[DataProvider('provideSwitchChanges')]
    public function testEveryChangeOfTheSwitchIsATrustChange(?bool $stored, ?bool $given): void
    {
        $connection = $this->saml(['metadata_refresh' => $stored]);
        $freshness  = FakeFreshness::fresh();

        $this->app?->instance(Freshness::class, $freshness);

        self::assertTrue(app(ConnectionService::class)->update(self::TENANT, $connection->id, ['settings' => ['metadata_refresh' => $given]], Clients::browser())->isChanged());
        self::assertSame([FreshnessOperation::CONNECTION_TRUST], array_column($freshness->asked(), 'operation'));
        self::assertSame(1, $this->row($connection)->trust_version);
    }

    /**
     * Only coming to hold a deadline clears the stamps; leaving, or staying in,
     * does not.
     *
     * @return void
     */
    public function testOnlyComingToHoldADeadlineClearsTheStamps(): void
    {
        $stamp    = ['metadata_fetched_at' => $this->clock->now()->subDays(1), 'metadata_refresh_at' => $this->clock->now()->addDay()];
        $leaving  = $this->saml(['metadata_refresh' => true], $stamp);
        $anchored = $this->saml([], $stamp);

        $this->anchor($anchored, self::idp()->certificate());
        $this->row($anchored)->forceFill($stamp)->save();

        app(ConnectionService::class)->update(self::TENANT, $leaving->id, ['settings' => ['metadata_refresh' => null]], Clients::browser());
        app(ConnectionService::class)->update(self::TENANT, $anchored->id, ['settings' => ['metadata_refresh' => true]], Clients::browser());

        self::assertSame('2026-10-31T09:30:00+00:00', $this->row($leaving)->metadata_fetched_at?->toIso8601String());
        self::assertNull($this->expiry()->expiresAt($this->row($leaving)));
        self::assertSame('2026-10-31T09:30:00+00:00', $this->row($anchored)->metadata_fetched_at?->toIso8601String());
        self::assertSame('2026-11-02T09:30:00+00:00', $this->row($anchored)->metadata_refresh_at?->toIso8601String());
        self::assertSame('2026-11-30T09:30:00+00:00', $this->expiry()->expiresAt($this->row($anchored))?->toIso8601String());
    }

    /**
     * Saving the URL on an anchored connection brings it in and clears old
     * stamps; other settings do not.
     *
     * @return void
     */
    public function testSavingAUrlOnAnAnchoredConnectionBringsItIn(): void
    {
        $connection = $this->saml(['metadata_url' => null], ['metadata_fetched_at' => $this->clock->now()->subDays(40)]);

        $this->anchor($connection, self::idp()->certificate());

        app(ConnectionService::class)->update(self::TENANT, $connection->id, ['settings' => ['force_authn' => true]], Clients::browser());

        self::assertSame('2026-09-22T09:30:00+00:00', $this->row($connection)->metadata_fetched_at?->toIso8601String());

        app(ConnectionService::class)->update(self::TENANT, $connection->id, ['settings' => ['metadata_url' => self::URL]], Clients::browser());

        self::assertNull($this->row($connection)->metadata_fetched_at);
        self::assertSame([$connection->id], $this->refresher()->dueConnectionIds());
    }

    /**
     * An administrator's refresh of a connection not opted in needs freshness,
     * replaces certificates and starts no clock.
     *
     * @return void
     */
    public function testARefreshNowOfAConnectionThatHasNotOptedInStartsNoClock(): void
    {
        $this->serve(self::metadata()->with(['signing_certificates' => [Certificates::distinct(2)]]));

        $connection = $this->saml();
        $freshness  = FakeFreshness::stale();

        $this->app?->instance(Freshness::class, $freshness);

        $refused = $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor(), Clients::browser());

        self::assertSame([RefreshOutcome::REFUSED, FailureReason::FRESHNESS_REQUIRED], [$refused->outcome, $refused->reason]);
        self::assertSame([FreshnessOperation::CONNECTION_TRUST], array_column($freshness->asked(), 'operation'));

        $this->fetcher->assertNothingFetched();

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $refreshed = $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor(), Clients::browser());
        $row       = $this->row($connection);

        self::assertSame(RefreshOutcome::REFRESHED, $refreshed->outcome);
        self::assertSame(['idp_signing_certificates'], $refreshed->changedSettings);
        self::assertSame(1, $row->metadata_version);
        self::assertSame('2026-11-01T09:30:00+00:00', $row->metadata_fetched_at?->toIso8601String());
        self::assertNull($this->expiry()->expiresAt($row));

        $this->clock->advance(86400 * 365);

        self::assertFalse($this->expiry()->isExpired($this->row($connection)));
        self::assertSame([], $this->refresher()->dueConnectionIds());
    }

    /**
     * A manual refresh's stamp starts no clock if the connection opts in a year
     * later.
     *
     * @return void
     */
    public function testARefreshByHandCannotExpireAConnectionThatOptsInLater(): void
    {
        $this->serve(self::metadata());

        $connection = $this->saml();

        self::assertTrue($this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor(), Clients::browser())->isRefreshed());

        $this->clock->advance(86400 * 365);

        app(ConnectionService::class)->update(self::TENANT, $connection->id, ['settings' => ['metadata_refresh' => true]], Clients::browser());

        self::assertFalse($this->expiry()->isExpired($this->row($connection)));
        self::assertSame([$connection->id], $this->refresher()->dueConnectionIds());
    }

    /**
     * An OIDC connection's document keeps its deadline with refresh off and no
     * anchor.
     *
     * @return void
     */
    public function testAnOidcConnectionKeepsItsDeadline(): void
    {
        $connection = $this->makeConnection(['protocol' => 'oidc', 'settings' => ['metadata_refresh' => false], 'metadata_fetched_at' => $this->clock->now()]);

        self::assertSame(self::LIMIT, $this->expiry()->expiresAt($connection)?->toIso8601String());

        $this->clock->advance(2592000);

        self::assertTrue($this->expiry()->isExpired($connection));
    }

    /**
     * Trust an anchor through the key service, answering its id.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $certificate
     * @return string
     */
    private function anchor(Connection $connection, string $certificate): string
    {
        self::assertTrue(app(KeyService::class)->trustCertificate(self::TENANT, $connection->id, $certificate, Clients::browser(), null, KeyUse::METADATA_SIGNING)->isSucceeded());

        $id = ConnectionKey::query()->where('connection_id', $connection->id)->where('use', KeyUse::METADATA_SIGNING->value)->latest('id')->value('id');

        self::assertIsString($id);

        return $id;
    }

    /**
     * A SAML connection of the tenant with a URL and no switch; a `null`
     * setting is left out.
     *
     * @param  array<string, mixed>  $settings
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(array $settings = [], array $attributes = []): Connection
    {
        $values = Saml2Settings::fromArray([
            'idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID,
            'sso_url'       => FakeSamlIdentityProvider::SSO_URL,
            'sso_binding'   => 'http_redirect',
            'metadata_url'  => self::URL,
            ...$settings,
        ])->toArray();

        return $this->makeConnection(['tenant_id' => self::TENANT, 'protocol' => 'saml2', 'enabled' => true, 'settings' => $values, ...$attributes]);
    }

    /**
     * The connection as stored now, read on the write connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function row(Connection $connection): Connection
    {
        return Connection::query()->useWritePdo()->findOrFail($connection->id);
    }

    /**
     * Serve the metadata at the URL.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata  $metadata
     * @return void
     */
    private function serve(FakeSamlMetadata $metadata): void
    {
        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], $metadata->toXml()));
    }

    /**
     * The refresher, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\MetadataRefresher
     */
    private function refresher(): MetadataRefresher
    {
        return app(MetadataRefresher::class);
    }

    /**
     * The expiry, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\MetadataExpiry
     */
    private function expiry(): MetadataExpiry
    {
        return app(MetadataExpiry::class);
    }

    /**
     * The provider's metadata.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata
     */
    private static function metadata(): FakeSamlMetadata
    {
        return self::idp()->metadata(FakeSamlIdentityProvider::SSO_URL);
    }

    /**
     * The provider, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }

    /**
     * The administrator who asked.
     *
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     */
    private static function actor(): Caller
    {
        return new Caller(new IdentityReference('App\Models\User', '42'));
    }
}
