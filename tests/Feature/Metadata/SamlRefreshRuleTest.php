<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Illuminate\Database\Migrations\Migration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
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
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for when a SAML connection follows its metadata URL (SSO-2.8),
 * through the services an administrator uses: an anchor or an explicit `true`
 * brings it in, `false` keeps it out, and with neither nothing changes by
 * itself and nothing expires. Adding an anchor turns the default on and
 * removing it turns the default off; whatever brings a connection in starts it
 * with no clock running and its first refresh due; opting in is a
 * freshness-gated trust change; and an administrator may still refresh a
 * connection that has not opted in, which leaves it holding no deadline.
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

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

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
     * Bind a fixed clock, a fake fetcher serving the provider's metadata signed
     * by its anchor and a fresh freshness contract, switch SAML and the refresh
     * on and create the tables.
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

        $this->createConnectionTables();
        $this->createFlowTables();
        self::rateLimitsMigration()->up(); // @phpstan-ignore method.notFound

        $this->serve(self::metadata()->with(['aggregate' => ['https://other.example.test/saml'], 'sign' => 'aggregate']));
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::rateLimitsMigration()->down(); // @phpstan-ignore method.notFound
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * Rows of `[anchored, switch, due]`: whether a connection with a URL is due
     * on the schedule.
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
     * The schedule lists a connection, and a queued refresh acts on it, by its
     * anchor and its switch; a run refreshes only those.
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
        self::assertSame($due ? RefreshOutcome::REFRESHED : RefreshOutcome::SKIPPED, $this->refresher()->refreshQueued($connection->id)->outcome);
        self::assertSame($due ? 1 : 0, $this->row($connection)->metadata_version);
        self::assertCount($due ? 1 : 0, $this->fetcher->requests());
    }

    /**
     * Every chunk of a due listing keeps its order, whichever connections its
     * anchors bring in.
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
     * Adding the first anchor turns the default on: the connection is due at
     * once, whatever refresh date a refresh by hand left, what was stamped
     * before it counted starts no clock, and its first refresh does.
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

        self::assertTrue($this->refresher()->refreshQueued($connection->id)->isRefreshed());
        self::assertSame(self::LIMIT, $this->expiry()->expiresAt($this->row($connection))?->toIso8601String());
    }

    /**
     * Removing the last anchor stops the default: the connection is no longer
     * due, and what was stamped while it was anchored no longer expires it, so
     * it keeps working with nothing needed to recover it.
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

        self::assertTrue(app(KeyService::class)->distrustCertificate(self::TENANT, $connection->id, $key)->isSucceeded());

        $row = $this->row($connection);

        self::assertSame(2, $row->trust_version);
        self::assertFalse($this->expiry()->isExpired($row));
        self::assertNull($this->expiry()->expiresAt($row));
        self::assertSame([], $this->refresher()->dueConnectionIds());
        self::assertSame(RefreshOutcome::SKIPPED, $this->refresher()->refreshQueued($connection->id)->outcome);
    }

    /**
     * An anchor removed and added again does not bring back what was stamped
     * before: it expired nothing while it held no deadline, and it expires
     * nothing now, until a refresh stamps it again.
     *
     * @return void
     */
    public function testAnAnchorAddedAgainDoesNotReviveAnOldStamp(): void
    {
        $connection = $this->saml();
        $key        = $this->anchor($connection, self::idp()->certificate());

        $this->row($connection)->forceFill(['metadata_fetched_at' => $this->clock->now()->subDays(40)])->save();

        app(KeyService::class)->distrustCertificate(self::TENANT, $connection->id, $key);

        self::assertFalse($this->expiry()->isExpired($this->row($connection)));

        $this->anchor($connection, self::idp()->certificate());

        self::assertFalse($this->expiry()->isExpired($this->row($connection)));
        self::assertNull($this->row($connection)->metadata_fetched_at);
    }

    /**
     * Another anchor on a connection already anchored, and removing one of two,
     * change nothing about its deadline or its refresh.
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

        app(KeyService::class)->distrustCertificate(self::TENANT, $connection->id, $second);

        self::assertSame(self::LIMIT, $this->expiry()->expiresAt($this->row($connection))?->toIso8601String());
    }

    /**
     * An anchor on a connection with `metadata_refresh` set `true` already, or
     * with no URL, brings nothing in, so it clears nothing; on one set `false`
     * it brings the deadline in but no refresh, and starts no clock.
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
     * An explicit `false` on an anchored connection is still off, and a
     * validated fetch still counts on it: an administrator's refresh stamps it,
     * and it expires with nothing on the schedule to refresh it.
     *
     * @return void
     */
    public function testFalseOnAnAnchoredConnectionIsOffAndKeepsTheFetchsDeadline(): void
    {
        $connection = $this->saml(['metadata_refresh' => false]);

        $this->anchor($connection, self::idp()->certificate());

        self::assertSame([], $this->refresher()->dueConnectionIds());
        self::assertTrue($this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor())->isRefreshed());
        self::assertSame(self::LIMIT, $this->expiry()->expiresAt($this->row($connection))?->toIso8601String());
        self::assertSame([], $this->refresher()->dueConnectionIds());

        $this->clock->advance(2592000);

        self::assertTrue($this->expiry()->isExpired($this->row($connection)));
        self::assertSame([], $this->refresher()->dueConnectionIds());
    }

    /**
     * Opting in with a stale authentication is refused: nothing changes, the
     * trust version and what is in flight stay as they were, and only the
     * connection's trust is asked.
     *
     * @return void
     */
    public function testOptingInRequiresFreshness(): void
    {
        $connection = $this->saml();
        $request    = $this->makeAuthorizationRequest($connection);
        $freshness  = FakeFreshness::stale();

        $this->app?->instance(Freshness::class, $freshness);

        $result = app(ConnectionService::class)->update(self::TENANT, $connection->id, ['settings' => ['metadata_refresh' => true]]);
        $row    = $this->row($connection);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertSame([FreshnessOperation::CONNECTION_TRUST], array_column($freshness->asked(), 'operation'));
        self::assertArrayNotHasKey('metadata_refresh', $row->settings);
        self::assertSame(0, $row->trust_version);
        self::assertNull($request->fresh()?->voided_at);
        self::assertSame([], $this->refresher()->dueConnectionIds());
    }

    /**
     * Opting in is a trust change: it raises the trust version, voids what is
     * in flight, is reported naming the setting, makes the connection due at
     * once and starts no clock from an old stamp, so it does not expire the
     * moment it opts in.
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

        $result = app(ConnectionService::class)->update(self::TENANT, $connection->id, ['settings' => ['metadata_refresh' => true]]);
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
     * Rows of `[stored, given]`: changes of the switch that are each a trust
     * change, whichever way they go.
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
     * Every change of the switch asks the connection's trust and raises its
     * trust version.
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

        self::assertTrue(app(ConnectionService::class)->update(self::TENANT, $connection->id, ['settings' => ['metadata_refresh' => $given]])->isChanged());
        self::assertSame([FreshnessOperation::CONNECTION_TRUST], array_column($freshness->asked(), 'operation'));
        self::assertSame(1, $this->row($connection)->trust_version);
    }

    /**
     * Leaving, and a change that stays in, leave the stamps alone: leaving
     * simply ends the deadline, and an anchored connection set `true` keeps the
     * clock its last fetch started.
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

        app(ConnectionService::class)->update(self::TENANT, $leaving->id, ['settings' => ['metadata_refresh' => null]]);
        app(ConnectionService::class)->update(self::TENANT, $anchored->id, ['settings' => ['metadata_refresh' => true]]);

        self::assertSame('2026-10-31T09:30:00+00:00', $this->row($leaving)->metadata_fetched_at?->toIso8601String());
        self::assertNull($this->expiry()->expiresAt($this->row($leaving)));
        self::assertSame('2026-10-31T09:30:00+00:00', $this->row($anchored)->metadata_fetched_at?->toIso8601String());
        self::assertSame('2026-11-02T09:30:00+00:00', $this->row($anchored)->metadata_refresh_at?->toIso8601String());
        self::assertSame('2026-11-30T09:30:00+00:00', $this->expiry()->expiresAt($this->row($anchored))?->toIso8601String());
    }

    /**
     * Saving the URL on an anchored connection brings it in as the anchor
     * would, clearing a stamp from before; another setting's change reads no
     * anchor and clears nothing.
     *
     * @return void
     */
    public function testSavingAUrlOnAnAnchoredConnectionBringsItIn(): void
    {
        $connection = $this->saml(['metadata_url' => null], ['metadata_fetched_at' => $this->clock->now()->subDays(40)]);

        $this->anchor($connection, self::idp()->certificate());

        app(ConnectionService::class)->update(self::TENANT, $connection->id, ['settings' => ['force_authn' => true]]);

        self::assertSame('2026-09-22T09:30:00+00:00', $this->row($connection)->metadata_fetched_at?->toIso8601String());

        app(ConnectionService::class)->update(self::TENANT, $connection->id, ['settings' => ['metadata_url' => self::URL]]);

        self::assertNull($this->row($connection)->metadata_fetched_at);
        self::assertSame([$connection->id], $this->refresher()->dueConnectionIds());
    }

    /**
     * An administrator's refresh of a connection that has not opted in needs a
     * fresh authentication, and then runs: the certificates are replaced from
     * the URL, yet it starts no clock and the schedule still leaves it alone.
     *
     * @return void
     */
    public function testARefreshNowOfAConnectionThatHasNotOptedInStartsNoClock(): void
    {
        $this->serve(self::metadata()->with(['signing_certificates' => [Certificates::distinct(2)]]));

        $connection = $this->saml();
        $freshness  = FakeFreshness::stale();

        $this->app?->instance(Freshness::class, $freshness);

        $refused = $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor());

        self::assertSame([RefreshOutcome::REFUSED, FailureReason::FRESHNESS_REQUIRED], [$refused->outcome, $refused->reason]);
        self::assertSame([FreshnessOperation::CONNECTION_TRUST], array_column($freshness->asked(), 'operation'));

        $this->fetcher->assertNothingFetched();

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $refreshed = $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor());
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
     * What a refresh by hand stamped starts no clock if the connection opts in
     * a year later.
     *
     * @return void
     */
    public function testARefreshByHandCannotExpireAConnectionThatOptsInLater(): void
    {
        $this->serve(self::metadata());

        $connection = $this->saml();

        self::assertTrue($this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor())->isRefreshed());

        $this->clock->advance(86400 * 365);

        app(ConnectionService::class)->update(self::TENANT, $connection->id, ['settings' => ['metadata_refresh' => true]]);

        self::assertFalse($this->expiry()->isExpired($this->row($connection)));
        self::assertSame([$connection->id], $this->refresher()->dueConnectionIds());
    }

    /**
     * Whatever a SAML connection does, an OIDC connection's document still
     * holds a deadline with its refresh off and no anchor.
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
        self::assertTrue(app(KeyService::class)->trustCertificate(self::TENANT, $connection->id, $certificate, null, KeyUse::METADATA_SIGNING)->isSucceeded());

        $id = ConnectionKey::query()->where('connection_id', $connection->id)->where('use', KeyUse::METADATA_SIGNING->value)->latest('id')->value('id');

        self::assertIsString($id);

        return $id;
    }

    /**
     * A SAML connection of the tenant with a URL and no switch, but for the
     * settings given, a `null` among them leaving one out.
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
     * @return \SineMacula\Laravel\Sso\Administration\ActingIdentity
     */
    private static function actor(): ActingIdentity
    {
        return new ActingIdentity('App\Models\User', '42');
    }

    /**
     * The shipped migration of the rate limit counters.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function rateLimitsMigration(): Migration
    {
        /** @var \Illuminate\Database\Migrations\Migration */
        return require dirname(__DIR__, 3) . self::RATE_LIMITS_MIGRATION;
    }
}
