<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Carbon\CarbonImmutable;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Random\RandomException;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\ImportResult;
use SineMacula\Laravel\Sso\Metadata\MetadataImporter;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\RefreshClaims;
use SineMacula\Laravel\Sso\Metadata\RefreshResult;
use SineMacula\Laravel\Sso\Metadata\RefreshWriter;
use SineMacula\Laravel\Sso\Metadata\SamlMetadataSource;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\Fixtures\Protocols\ExampleDriver;
use Tests\TestCase;

/**
 * Feature tests for the scheduled and on-demand refresh of SAML metadata
 * (SSO-2.8, SSO-2.9, SSO-11.12), through the fake fetcher and the fake
 * identity provider's metadata: which connections are due (the feature, the
 * switch, the URL, the backoff and the claim); the saved URL fetched as a
 * metadata request; an additive certificate voiding nothing, a removed one or
 * a moved endpoint voiding the flows in flight; another entity, a missing
 * signature and a failed fetch recorded as failures, backing off and logged
 * with the reason and the fetch's status alone; a malformed aggregate expiry,
 * or a reader that throws, recorded as a failure of that connection alone, the
 * run going on; a refresh now skipping the backoff but never a held claim; a
 * refused refresh now; no run inside a transaction; and what a refresh applied
 * expiring at the driver after the stale limit, or never with no limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataRefresher::class)]
#[CoversClass(RefreshClaims::class)]
#[CoversClass(SamlMetadataSource::class)]
#[CoversClass(RefreshWriter::class)]
final class MetadataRefresherTest extends TestCase
{
    use CapturesLogs, RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var string The tenant whose connection refreshes. */
    private const string TENANT = 'tenant-1';

    /** @var string The URL the provider serves its metadata at. */
    private const string URL = 'https://idp.example.test/metadata.xml';

    /** @var string The URL a second provider serves its metadata at. */
    private const string SECOND_URL = 'https://idp.example.test/second.xml';

    /** @var string The single sign-on URL the provider moves to. */
    private const string MOVED_URL = 'https://login.example.test/saml/sso';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the refresh fetches through. */
    private FakeFetcher $fetcher;

    /**
     * Bind a fixed clock and a fake fetcher serving the provider's metadata,
     * switch SAML and the refresh on, create the tables (the rate limit
     * counters' among them), and record events.
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

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.metadata_refresh', true);
        config()->set('sso.endpoints.base_url', 'https://api.example.com');

        $this->createConnectionTables();
        $this->createFlowTables();
        self::rateLimitsMigration()->up(); // @phpstan-ignore method.notFound

        $this->serve(self::metadata());
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
        self::rateLimitsMigration()->down(); // @phpstan-ignore method.notFound
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A due connection is refreshed once, through the saved URL fetched as a
     * metadata request with no credential, and is due again only after the
     * refresh interval.
     *
     * @return void
     */
    public function testADueConnectionIsRefreshedOnceUntilTheIntervalEnds(): void
    {
        $connection = $this->saml();
        $results    = $this->refresher()->refreshDue();

        self::assertSame([[RefreshOutcome::REFRESHED, $connection->id, [], 1, false]], self::summaries($results));
        self::assertSame([[FetchPurpose::METADATA, self::URL, null]], array_map(
            static fn (FetchRequest $request): array => [$request->purpose, $request->url, $request->credentials],
            $this->fetcher->requests(),
        ));
        self::assertSame([], $this->refresher()->refreshDue());

        $this->clock->advance(86399);

        self::assertSame([], $this->refresher()->refreshDue());

        $this->clock->advance(1);

        self::assertCount(1, app(MetadataRefresher::class)->refreshDue());
        self::assertCount(2, $this->fetcher->requests());
    }

    /**
     * Rows of `[attributes, settings, due]`: a connection's refresh state and
     * settings, and whether it is due now.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: bool}>
     */
    public static function provideDueness(): iterable
    {
        $at = static fn (string $instant): CarbonImmutable => CarbonImmutable::parse($instant);

        yield from [
            'never refreshed'            => [[], [], true],
            'due now'                    => [['metadata_refresh_at' => $at('2026-11-01T09:30:00Z')], [], true],
            'due a second ago'           => [['metadata_refresh_at' => $at('2026-11-01T09:29:59Z')], [], true],
            'due in a second'            => [['metadata_refresh_at' => $at('2026-11-01T09:30:01Z')], [], false],
            'claimed for a second more'  => [['metadata_claimed_until' => $at('2026-11-01T09:30:01Z')], [], false],
            'claimed until now'          => [['metadata_claimed_until' => $at('2026-11-01T09:30:00Z')], [], true],
            'claimed until a second ago' => [['metadata_claimed_until' => $at('2026-11-01T09:29:59Z')], [], true],
            'the switch off'             => [[], ['metadata_refresh' => false], false],
            'the switch not true'        => [[], ['metadata_refresh' => 'true'], false],
            'no metadata URL'            => [[], ['metadata_url' => null], false],
            'a metadata URL over HTTP'   => [[], ['metadata_url' => 'http://idp.example.test/metadata.xml'], false],
            'an OIDC connection'         => [['protocol' => 'oidc'], [], false],
        ];
    }

    /**
     * Only a SAML connection switched on with an `https` metadata URL, whose
     * next refresh is due and on which no claim holds, is refreshed.
     *
     * @param  array<string, mixed>  $attributes
     * @param  array<string, mixed>  $settings
     * @param  bool  $due
     * @return void
     */
    #[DataProvider('provideDueness')]
    public function testOnlyADueConnectionThatRefreshesIsRefreshed(array $attributes, array $settings, bool $due): void
    {
        $this->saml($settings, $attributes);

        self::assertCount($due ? 1 : 0, $this->refresher()->refreshDue());
        self::assertCount($due ? 1 : 0, $this->fetcher->requests());
    }

    /**
     * With the feature off nothing is due, whatever the connections.
     *
     * @return void
     */
    public function testNothingIsDueWithTheFeatureOff(): void
    {
        $this->saml();

        config()->set('sso.features.metadata_refresh', false);

        self::assertSame([], $this->refresher()->refreshDue());

        $this->fetcher->assertNothingFetched();
    }

    /**
     * With SAML switched off and OIDC on, nothing of SAML refreshes: it is not
     * listed as due nor refreshed, a queued job skips it and an administrator
     * is refused, with nothing fetched, written or reported.
     *
     * @return void
     */
    public function testNothingOfAProtocolSwitchedOffRefreshes(): void
    {
        $connection = $this->saml();
        $before     = self::refreshState($this->row($connection));

        config()->set('sso.features.saml2', false);
        config()->set('sso.features.oidc', true);

        self::assertSame([], $this->refresher()->dueConnectionIds());
        self::assertSame([], $this->refresher()->refreshDue());

        $queued  = $this->refresher()->refreshQueued($connection->id);
        $refused = $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor());

        self::assertSame([RefreshOutcome::SKIPPED, $connection->id], [$queued->outcome, $queued->connectionId]);
        self::assertSame([RefreshOutcome::REFUSED, FailureReason::FEATURE_DISABLED, $connection->id], [$refused->outcome, $refused->reason, $refused->connectionId]);
        self::assertSame($before, self::refreshState($this->row($connection)));

        $this->fetcher->assertNothingFetched();
        $this->assertNoEvents();
    }

    /**
     * A protocol switched off does not stop another that is on, and its
     * connections page past in the listing.
     *
     * @return void
     */
    public function testAProtocolSwitchedOffLeavesTheOtherRefreshing(): void
    {
        config()->set('sso.features.oidc', false);

        $oidc = $this->makeConnection(['protocol' => 'oidc', 'settings' => ['issuer' => 'https://op.example.test', 'metadata_refresh' => true]]);
        $saml = $this->saml();

        self::assertSame([$saml->id], $this->refresher()->dueConnectionIds());
        self::assertSame(RefreshOutcome::SKIPPED, $this->refresher()->refreshQueued($oidc->id)->outcome);
        self::assertSame([$saml->id], array_map(static fn (RefreshResult $result): string => (string) $result->connectionId, $this->refresher()->refreshDue()));
    }

    /**
     * Every due connection is refreshed, in id order, across chunks.
     *
     * @return void
     */
    public function testEveryDueConnectionIsRefreshedInIdOrderAcrossChunks(): void
    {
        $ids = [];

        foreach (range(1, MetadataRefresher::CHUNK_SIZE + 2) as $index) {
            $ids[] = $this->saml([], ['id' => sprintf('01jb%022d', $index)])->id;
        }

        $results = $this->refresher()->refreshDue();

        self::assertSame($ids, array_map(static fn (RefreshResult $result): ?string => $result->connectionId, $results));
        self::assertSame(['refreshed'], array_values(array_unique(array_map(static fn (RefreshResult $result): string => $result->outcome->value, $results))));
    }

    /**
     * Rows of `[change]`: what another server writes to a connection after the
     * run listed it.
     *
     * @return iterable<string, array{0: array<string, int|string>}>
     */
    public static function provideChangesAfterListing(): iterable
    {
        yield from [
            'claimed'   => [['metadata_claimed_until' => '2026-11-01 09:35:00']],
            'refreshed' => [['metadata_version' => 1]],
        ];
    }

    /**
     * A connection another server claims or refreshes after the run listed it
     * is skipped, with nothing fetched for it.
     *
     * @param  array<string, int|string>  $change
     * @return void
     */
    #[DataProvider('provideChangesAfterListing')]
    public function testAConnectionChangedAfterItWasListedIsSkipped(array $change): void
    {
        $first  = $this->saml([], ['id' => '01jb0000000000000000000001']);
        $second = $this->saml(['metadata_url' => 'https://idp.example.test/second.xml'], ['id' => '01jb0000000000000000000002']);
        $xml    = self::metadata()->toXml();

        $this->fetcher->respond(self::URL, static function (FetchRequest $request) use ($second, $xml, $change): FetchResult {
            unset($request);

            Connection::query()->whereKey($second->id)->update($change);

            return FetchResult::fetched(200, [], $xml);
        });

        self::assertSame(
            [[RefreshOutcome::REFRESHED, $first->id, [], 1, false], [RefreshOutcome::SKIPPED, $second->id, [], null, false]],
            self::summaries($this->refresher()->refreshDue()),
        );
        self::assertCount(1, $this->fetcher->requests());
    }

    /**
     * A certificate the provider publishes beside the one trusted is trusted,
     * and the flow in flight is not voided.
     *
     * @return void
     */
    public function testAnAdditiveCertificateDoesNotVoidAFlowInFlight(): void
    {
        $connection = $this->saml();
        $request    = $this->makeAuthorizationRequest($connection);

        $this->serve(self::metadata()->with(['signing_certificates' => [self::idp()->certificate(), Certificates::distinct(5)]]));

        self::assertSame([[RefreshOutcome::REFRESHED, $connection->id, ['idp_signing_certificates'], 1, false]], self::summaries($this->refresher()->refreshDue()));
        self::assertSame(0, $this->row($connection)->trust_version);
        self::assertNull($request->refresh()->voided_at);
        self::assertSame(2, ConnectionKey::query()->where('use', KeyUse::IDP_SIGNING->value)->count());
    }

    /**
     * A certificate no longer published, or a moved single sign-on URL, voids
     * the flow in flight and raises the trust version.
     *
     * @return void
     */
    public function testARemovedCertificateOrAMovedEndpointVoidsAFlowInFlight(): void
    {
        $connection = $this->saml();

        $this->trust($connection, Certificates::distinct(6));

        $request = $this->makeAuthorizationRequest($connection);

        self::assertSame([[RefreshOutcome::REFRESHED, $connection->id, ['idp_signing_certificates'], 1, true]], self::summaries($this->refresher()->refreshDue()));
        self::assertNotNull($request->refresh()->voided_at);
        self::assertSame(1, $this->row($connection)->trust_version);

        $moved = $this->makeAuthorizationRequest($connection);

        $this->serve(self::metadata(self::MOVED_URL));
        $this->clock->advance(86400);

        self::assertSame([[RefreshOutcome::REFRESHED, $connection->id, ['sso_url'], 2, true]], self::summaries($this->refresher()->refreshDue()));
        self::assertNotNull($moved->refresh()->voided_at);
        self::assertSame([2, self::MOVED_URL], [$this->row($connection)->trust_version, $this->row($connection)->settings['sso_url']]);
    }

    /**
     * Rows of `[response, reason, fetch status]`: a fetch that brought no
     * metadata, the reason the refresh failed for, and the fetch's status.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchResult, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason, 2: string}>
     */
    public static function provideFailedFetches(): iterable
    {
        yield from [
            'refused'        => [FetchResult::refused(), FailureReason::FETCH_REFUSED, 'refused'],
            'failed'         => [FetchResult::failed(), FailureReason::FETCH_FAILED, 'failed'],
            'a server error' => [FetchResult::fetched(503, [], 'down for maintenance'), FailureReason::FETCH_FAILED, 'fetched'],
        ];
    }

    /**
     * A fetch that brought no metadata records a failure, keeps the last good
     * settings, and is logged with the reason and the fetch's status alone.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $response
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  string  $status
     * @return void
     */
    #[DataProvider('provideFailedFetches')]
    public function testAFailedFetchIsRecordedAndLoggedWithoutAValue(FetchResult $response, FailureReason $reason, string $status): void
    {
        $this->captureLogs();

        $connection = $this->saml();
        $before     = $this->row($connection)->settings;

        $this->fetcher->respond(self::URL, $response);

        $result = $this->refresher()->refreshDue()[0];

        self::assertSame(
            [RefreshOutcome::FAILED, $reason, 1, '2026-11-01T09:35:00+00:00'],
            [$result->outcome, $result->reason, $result->failures, $result->nextAttemptAt?->toIso8601String()],
        );
        self::assertSame($before, $this->row($connection)->settings);
        self::assertSame([[
            'channel' => 'sso_capture',
            'level'   => 'warning',
            'message' => 'sso.metadata.refresh_failed',
            'context' => ['reason' => $reason->value, 'fetch_status' => $status],
        ]], $this->capturedLogRecords());

        $this->assertNothingLoggedContains(self::URL, 'idp.example.test', 'down for maintenance');
    }

    /**
     * Rows of `[metadata, anchored, reason]`: metadata the refresh refuses,
     * whether the connection has an anchor, and the reason.
     *
     * @return iterable<string, array{0: \Closure(): string, 1: bool, 2: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideRefusedMetadata(): iterable
    {
        yield from [
            'another entity' => [
                static fn (): string => self::metadata()->with(['entity_id' => 'https://renamed.example.test/saml'])->toXml(),
                false,
                FailureReason::METADATA_ENTITY_NOT_FOUND,
            ],
            'unsigned, with an anchor' => [static fn (): string => self::metadata()->toXml(), true, FailureReason::METADATA_SIGNATURE_INVALID],
            'not metadata'             => [static fn (): string => '<html lang="en"></html>', false, FailureReason::METADATA_INVALID],
            'expired'                  => [
                static fn (): string => self::metadata()->with(['valid_until' => CarbonImmutable::parse('2026-11-01T09:00:00Z')])->toXml(),
                false,
                FailureReason::METADATA_EXPIRED,
            ],
        ];
    }

    /**
     * Metadata the reader refuses is recorded as a failure with its reason, and
     * changes nothing: the entity id is pinned, and a refresh never moves it.
     *
     * @param  \Closure(): string  $xml
     * @param  bool  $anchored
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefusedMetadata')]
    public function testRefusedMetadataIsRecordedAsAFailure(\Closure $xml, bool $anchored, FailureReason $reason): void
    {
        $connection = $this->saml();

        if ($anchored) {
            $this->trust($connection, self::idp()->certificate(), KeyUse::METADATA_SIGNING);
        }

        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], $xml()));

        $result = $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor());
        $row    = $this->row($connection);

        self::assertSame([RefreshOutcome::FAILED, $reason], [$result->outcome, $result->reason]);
        self::assertSame([FakeSamlIdentityProvider::ENTITY_ID, 0, 1], [$row->settings['idp_entity_id'], $row->metadata_version, $row->metadata_refresh_failures]);
    }

    /**
     * An aggregate whose `validUntil` names no real instant fails its
     * connection's refresh as invalid metadata: the failure is recorded, the
     * next attempt backs off, the claim is released, nothing is applied and the
     * value is logged nowhere; the run goes on to refresh the next connection
     * due.
     *
     * @return void
     */
    public function testAMalformedAggregateExpiryIsRecordedAndTheRunGoesOn(): void
    {
        $this->captureLogs();

        $malformed = $this->saml([], ['id' => '01jb0000000000000000000001']);
        $next      = $this->saml(['metadata_url' => self::SECOND_URL], ['id' => '01jb0000000000000000000002']);
        $aggregate = self::metadata()->with(['aggregate' => ['https://other.example.test/saml']])->toXml();

        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], str_replace('ID="_aggregate"', 'ID="_aggregate" validUntil="2026-13-01T00:00:00Z"', $aggregate)));
        $this->fetcher->respond(self::SECOND_URL, FetchResult::fetched(200, [], self::metadata()->toXml()));

        $results = $this->refresher()->refreshDue();

        self::assertCount(2, $results);
        self::assertSame(
            [$malformed->id, RefreshOutcome::FAILED, FailureReason::METADATA_INVALID, 1, '2026-11-01T09:35:00+00:00'],
            [$results[0]->connectionId, $results[0]->outcome, $results[0]->reason, $results[0]->failures, $results[0]->nextAttemptAt?->toIso8601String()],
        );
        self::assertSame([[RefreshOutcome::REFRESHED, $next->id, [], 1, false]], self::summaries([$results[1]]));
        self::assertSame([0, 1, '2026-11-01T09:35:00+00:00', null, null], self::refreshState($this->row($malformed)));
        self::assertSame([[
            'channel' => 'sso_capture',
            'level'   => 'warning',
            'message' => 'sso.metadata.refresh_failed',
            'context' => ['reason' => 'metadata_invalid', 'fetch_status' => 'fetched'],
        ]], $this->capturedLogRecords());

        $this->assertNothingLoggedContains('2026-13-01');
    }

    /**
     * A reader that throws rather than refusing the document fails the refresh
     * as invalid metadata, recorded like any other failure, with the exception
     * logged by its class alone.
     *
     * @return void
     */
    public function testAReaderThatThrowsIsRecordedAsInvalidMetadata(): void
    {
        $this->captureLogs();

        $connection = $this->saml();

        // The cap is read again by the reader once the fetch is done, and
        // throws then
        $this->fetcher->respond(self::URL, static function (): FetchResult {
            config()->set('sso.metadata.max_bytes', 'unreadable');

            return FetchResult::fetched(200, [], self::metadata()->toXml());
        });

        $result = $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor());

        self::assertSame([RefreshOutcome::FAILED, FailureReason::METADATA_INVALID, 1], [$result->outcome, $result->reason, $result->failures]);
        self::assertSame([0, 1, '2026-11-01T09:35:00+00:00', null, null], self::refreshState($this->row($connection)));
        self::assertSame([
            ['level' => 'warning', 'message' => 'sso.metadata.refresh_contained', 'context' => ['exception' => \InvalidArgumentException::class]],
            ['level' => 'warning', 'message' => 'sso.metadata.refresh_failed', 'context' => ['reason' => 'metadata_invalid', 'fetch_status' => 'fetched']],
        ], self::messages($this->capturedLogRecords()));
    }

    /**
     * A connection with no pinned entity id finds no entity, so its refresh
     * fails and changes nothing.
     *
     * @return void
     */
    public function testAConnectionWithNoPinnedEntityIdFindsNoEntity(): void
    {
        $connection = $this->saml(['idp_entity_id' => null]);
        $result     = $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor());

        self::assertSame([RefreshOutcome::FAILED, FailureReason::METADATA_ENTITY_NOT_FOUND], [$result->outcome, $result->reason]);
        self::assertArrayNotHasKey('idp_entity_id', $this->row($connection)->settings);
    }

    /**
     * Metadata signed by the connection's anchor is refreshed.
     *
     * @return void
     */
    public function testMetadataSignedByTheAnchorIsRefreshed(): void
    {
        $connection = $this->saml();

        $this->trust($connection, self::idp()->certificate(), KeyUse::METADATA_SIGNING);
        $this->serve(self::metadata()->with(['aggregate' => ['https://other.example.test/saml'], 'sign' => 'aggregate']));

        self::assertTrue($this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor())->isRefreshed());
    }

    /**
     * Failures in a row are retried as each backoff ends, 5 minutes doubling to
     * 6 hours, not a second before; a success resets the backoff.
     *
     * @return void
     */
    public function testFailuresBackOffUntilASuccess(): void
    {
        $connection = $this->saml();
        $waits      = [];

        $this->fetcher->respond(self::URL, FetchResult::failed());

        foreach (range(1, 9) as $failure) {

            $result  = $this->refresher()->refreshDue()[0] ?? null;
            $wait    = (int) $this->clock->now()->diffInSeconds($result?->nextAttemptAt);
            $waits[] = $wait;

            self::assertSame($failure, $result?->failures);

            $this->clock->advance($wait - 1);

            self::assertSame([], $this->refresher()->refreshDue());

            $this->clock->advance(1);
        }

        self::assertSame([300, 600, 1200, 2400, 4800, 9600, 19200, 21600, 21600], $waits);

        $this->serve(self::metadata());

        self::assertTrue($this->refresher()->refreshDue()[0]->isRefreshed());
        self::assertSame(0, $this->row($connection)->metadata_refresh_failures);
        self::assertSame($this->clock->now()->addDay()->toIso8601String(), $this->row($connection)->metadata_refresh_at?->toIso8601String());
    }

    /**
     * A refresh now runs whatever the backoff, for the administrator who asked.
     *
     * @return void
     */
    public function testARefreshNowSkipsTheBackoff(): void
    {
        $connection = $this->saml([], ['metadata_refresh_at' => $this->clock->now()->addHours(6), 'metadata_refresh_failures' => 8]);

        self::assertSame([], $this->refresher()->refreshDue());

        $result = $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor());

        self::assertSame([[RefreshOutcome::REFRESHED, $connection->id, [], 1, false]], self::summaries([$result]));
        self::assertSame(0, $this->row($connection)->metadata_refresh_failures);
        self::assertCount(1, $this->fetcher->requests());
    }

    /**
     * A refresh now never skips a claim another server holds: it is
     * `in_progress`, fetches nothing and reports nothing; a claim run out is
     * taken.
     *
     * @return void
     */
    public function testARefreshNowNeverSkipsAHeldClaim(): void
    {
        $connection = $this->saml([], ['metadata_claimed_until' => $this->clock->now()->addSecond()]);
        $result     = $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor());

        self::assertSame([RefreshOutcome::IN_PROGRESS, FailureReason::METADATA_REFRESH_IN_PROGRESS, $connection->id], [$result->outcome, $result->reason, $result->connectionId]);
        self::assertSame('2026-11-01T09:30:01+00:00', $this->row($connection)->metadata_claimed_until?->toIso8601String());

        $this->fetcher->assertNothingFetched();
        $this->assertNoEvents();

        $this->clock->advance(1);

        self::assertTrue($this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor())->isRefreshed());
    }

    /**
     * A refresh now counts against the connection's metadata limit before it
     * claims or fetches anything: past the limit it is `rate_limited` with the
     * seconds until the window ends, claims, fetches, writes and reports
     * nothing; the schedule is never counted.
     *
     * @return void
     */
    public function testARefreshNowIsRateLimitedBeforeItFetches(): void
    {
        config()->set('sso.rate_limits.metadata.per_connection', ['max' => 2, 'decay_seconds' => 3600]);

        $connection = $this->saml();

        self::assertTrue($this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor())->isRefreshed());
        self::assertTrue($this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor())->isRefreshed());

        $this->startRecordingEvents();

        $before  = $this->row($connection)->getAttributes();
        $limited = $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor());

        self::assertSame(
            [RefreshOutcome::RATE_LIMITED, FailureReason::RATE_LIMITED, $connection->id, 1800],
            [$limited->outcome, $limited->reason, $limited->connectionId, $limited->retryAfter],
        );
        self::assertSame($before, $this->row($connection)->getAttributes());
        self::assertCount(2, $this->fetcher->requests());
        $this->assertNoEvents();

        $this->row($connection)->forceFill(['metadata_refresh_at' => null])->save();

        self::assertSame(RefreshOutcome::REFRESHED, $this->refresher()->refreshDue()[0]->outcome ?? null);

        $this->clock->advance(1799);

        self::assertSame(RefreshOutcome::RATE_LIMITED, $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor())->outcome);

        $this->clock->advance(1);

        self::assertTrue($this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor())->isRefreshed());
    }

    /**
     * A refresh now and a URL import naming the connection draw from one limit,
     * either way round: imports that fill it leave a refresh now
     * `rate_limited`, and refreshes now that fill it leave an import so, each
     * having fetched nothing more.
     *
     * @return void
     */
    public function testARefreshNowSharesItsLimitWithAnImport(): void
    {
        config()->set('sso.rate_limits.metadata.per_connection', ['max' => 2, 'decay_seconds' => 3600]);

        $imported  = $this->saml();
        $refreshed = $this->saml();
        $importer  = app(MetadataImporter::class);
        $import    = static fn (Connection $connection): ImportResult => $importer->importUrl(self::TENANT, $connection->id, self::URL, FakeSamlIdentityProvider::ENTITY_ID);

        self::assertTrue($import($imported)->isProposed());
        self::assertTrue($import($imported)->isProposed());
        self::assertSame(RefreshOutcome::RATE_LIMITED, $this->refresher()->refreshNow(self::TENANT, $imported->id, self::actor())->outcome);

        self::assertTrue($this->refresher()->refreshNow(self::TENANT, $refreshed->id, self::actor())->isRefreshed());
        self::assertTrue($this->refresher()->refreshNow(self::TENANT, $refreshed->id, self::actor())->isRefreshed());
        self::assertSame([true, 1800], [$import($refreshed)->isRateLimited(), $import($refreshed)->retryAfter]);

        self::assertCount(4, $this->fetcher->requests());
    }

    /**
     * A refresh fetches through the metadata cap, never the fetcher's: the
     * request carries the cap, and a document over it fails the fetch, at it is
     * applied.
     *
     * @return void
     */
    public function testARefreshFetchesHeldToTheMetadataCap(): void
    {
        $xml = str_pad(self::metadata()->toXml(), 70000, "\n");

        config()->set('sso.metadata.max_bytes', 69999);
        config()->set('sso.fetcher.max_response_bytes', 1024);

        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], $xml));

        $connection = $this->saml();
        $over       = $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor());

        self::assertSame([RefreshOutcome::FAILED, FailureReason::FETCH_FAILED], [$over->outcome, $over->reason]);
        self::assertSame(69999, $this->fetcher->requests()[0]->maxBytes);

        config()->set('sso.metadata.max_bytes', 70000);

        self::assertTrue($this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor())->isRefreshed());
        self::assertSame(70000, $this->fetcher->requests()[1]->maxBytes);
    }

    /**
     * The fetch a refresh records is the moment the document was validated,
     * after the fetch, never a moment before it.
     *
     * @return void
     */
    public function testTheFetchRecordedIsWhenTheDocumentWasValidated(): void
    {
        $clock = $this->clock;

        $this->fetcher->respond(self::URL, static function () use ($clock): FetchResult {
            $clock->advance(7);

            return FetchResult::fetched(200, [], self::metadata()->toXml());
        });

        $connection = $this->saml();

        self::assertTrue($this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor())->isRefreshed());
        self::assertSame('2026-11-01T09:30:07+00:00', $this->row($connection)->metadata_fetched_at?->toIso8601String());
    }

    /**
     * A claim is written with a fresh random token, which the write that ends
     * the refresh releases with the claim.
     *
     * @return void
     */
    public function testAClaimCarriesATokenItsWriteReleases(): void
    {
        $connection = $this->saml();
        $tokens     = [];

        $this->fetcher->respond(self::URL, function () use ($connection, &$tokens): FetchResult {
            $tokens[] = [$this->row($connection)->metadata_claim_token, $this->row($connection)->metadata_claimed_until?->toIso8601String()];

            return FetchResult::fetched(200, [], self::metadata()->toXml());
        });

        $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor());
        $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor());

        self::assertCount(2, $tokens);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', (string) $tokens[0][0]);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', (string) $tokens[1][0]);
        self::assertNotSame($tokens[0][0], $tokens[1][0]);
        self::assertSame('2026-11-01T09:35:00+00:00', $tokens[0][1]);
        self::assertSame([null, null], [$this->row($connection)->metadata_claim_token, $this->row($connection)->metadata_claimed_until]);
    }

    /**
     * A refresh whose claim expired and was taken over while it fetched writes
     * nothing, and leaves the new owner's claim; a failed fetch likewise.
     *
     * @return void
     */
    public function testARefreshWhoseClaimWasTakenOverWhileItFetchedWritesNothing(): void
    {
        $connection = $this->saml();

        foreach ([self::metadata()->toXml(), null] as $served) {

            $this->fetcher->respond(self::URL, function () use ($connection, $served): FetchResult {
                Connection::query()->whereKey($connection->id)->update(['metadata_claim_token' => str_repeat('b', 32)]);

                return $served === null ? FetchResult::failed() : FetchResult::fetched(200, [], $served);
            });

            $result = $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor());

            self::assertSame([RefreshOutcome::CONFLICT, FailureReason::METADATA_CONFLICT], [$result->outcome, $result->reason]);
            self::assertSame([str_repeat('b', 32), 0, 0], [
                $this->row($connection)->metadata_claim_token,
                $this->row($connection)->metadata_version,
                $this->row($connection)->metadata_refresh_failures,
            ]);

            Connection::query()->whereKey($connection->id)->update(['metadata_claim_token' => null, 'metadata_claimed_until' => null]);
        }
    }

    /**
     * An administrator's certificate added while the refresh fetched is kept:
     * the refresh, which would have replaced the certificates exactly, is a
     * conflict and writes nothing.
     *
     * @return void
     */
    public function testACertificateAddedWhileTheRefreshFetchedIsKept(): void
    {
        $connection = $this->saml();

        $this->fetcher->respond(self::URL, function () use ($connection): FetchResult {
            $this->trust($connection, Certificates::distinct(5));

            return FetchResult::fetched(200, [], self::metadata()->toXml());
        });

        $result = $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor());

        self::assertSame(RefreshOutcome::CONFLICT, $result->outcome);
        self::assertCount(2, ConnectionKey::query()->where('connection_id', $connection->id)->where('use', KeyUse::IDP_SIGNING->value)->get());
    }

    /**
     * The schedule lists the ids of the connections due that refresh, in id
     * order, and nothing while the refresh is off; a queued refresh refreshes
     * its connection while it is still due, and is `skipped` once it is not,
     * for a connection gone, or one that no longer refreshes.
     *
     * @return void
     */
    public function testTheScheduleListsTheDueConnectionsAndAQueuedRefreshChecksItIsStillDue(): void
    {
        $one   = $this->saml();
        $two   = $this->saml();
        $off   = $this->saml(['metadata_refresh' => false]);
        $later = $this->saml([], ['metadata_refresh_at' => $this->clock->now()->addSecond()]);

        $expected = [$one->id, $two->id];

        sort($expected);

        self::assertSame($expected, $this->refresher()->dueConnectionIds());
        self::assertTrue($this->refresher()->refreshQueued($one->id)->isRefreshed());
        self::assertSame(
            [RefreshOutcome::SKIPPED, RefreshOutcome::SKIPPED, RefreshOutcome::SKIPPED, RefreshOutcome::SKIPPED],
            [
                $this->refresher()->refreshQueued($one->id)->outcome,
                $this->refresher()->refreshQueued($off->id)->outcome,
                $this->refresher()->refreshQueued($later->id)->outcome,
                $this->refresher()->refreshQueued('01jbunknownconnection00000')->outcome,
            ],
        );

        config()->set('sso.features.metadata_refresh', false);

        self::assertSame([[], RefreshOutcome::SKIPPED], [$this->refresher()->dueConnectionIds(), $this->refresher()->refreshQueued($two->id)->outcome]);
        self::assertCount(1, $this->fetcher->requests());
    }

    /**
     * Rows of `[kind, reason]`: a refresh now that is refused before anything
     * runs.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideRefusals(): iterable
    {
        yield from [
            'an unknown connection'      => ['unknown', FailureReason::CONNECTION_NOT_FOUND],
            'another tenants connection' => ['other-tenant', FailureReason::CONNECTION_NOT_FOUND],
            'the feature off'            => ['feature-off', FailureReason::FEATURE_DISABLED],
            'the switch off'             => ['switch-off', FailureReason::FEATURE_DISABLED],
            'an OIDC connection'         => ['oidc', FailureReason::FEATURE_DISABLED],
        ];
    }

    /**
     * A refresh now of no such connection, or of one whose metadata does not
     * refresh, is refused with nothing fetched, written or reported.
     *
     * @param  string  $kind
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testARefreshNowIsRefusedForAConnectionThatDoesNotRefresh(string $kind, FailureReason $reason): void
    {
        $connection = match ($kind) {
            'other-tenant' => $this->saml([], ['tenant_id' => 'tenant-2']),
            'switch-off'   => $this->saml(['metadata_refresh' => false]),
            'oidc'         => $this->saml([], ['protocol' => 'oidc']),
            default        => $this->saml(),
        };

        config()->set('sso.features.metadata_refresh', $kind !== 'feature-off');

        $id     = $kind === 'unknown' ? '01jbunknownconnection00000' : $connection->id;
        $result = $this->refresher()->refreshNow(self::TENANT, $id, self::actor());
        $named  = $reason === FailureReason::CONNECTION_NOT_FOUND ? null : $connection->id;

        self::assertSame([RefreshOutcome::REFUSED, $reason, $named], [$result->outcome, $result->reason, $result->connectionId]);

        $this->fetcher->assertNothingFetched();
        $this->assertNoEvents();
    }

    /**
     * No refresh, nor the listing of the due connections, runs inside a
     * transaction on the storage connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNeitherRefreshRunsInsideATransaction(): void
    {
        $connection = $this->saml();
        $refreshes  = [
            fn (): mixed => $this->refresher()->refreshDue(),
            fn (): mixed => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor()),
            fn (): mixed => $this->refresher()->dueConnectionIds(),
            fn (): mixed => $this->refresher()->refreshQueued($connection->id),
        ];

        foreach ($refreshes as $refresh) {
            try {
                DB::connection(StorageConnection::name())->transaction($refresh);
                self::fail('A refresh ran inside a transaction.');
            } catch (\LogicException $exception) {
                self::assertSame('A metadata refresh runs outside any transaction on the storage connection, since it fetches before it writes.', $exception->getMessage());
            }
        }

        $this->fetcher->assertNothingFetched();
    }

    /**
     * What a refresh applied stops being used the stale limit after it: the
     * driver refuses a start with `metadata_expired` from that instant, and not
     * a second before.
     *
     * @return void
     */
    public function testTheStaleLimitExpiresWhatARefreshAppliedAtTheDriver(): void
    {
        $connection = $this->saml();

        $this->refresher()->refreshDue();
        $this->clock->advance(2592000 - 1);

        self::assertNull($this->startReason($connection));

        $this->clock->advance(1);

        self::assertSame(FailureReason::METADATA_EXPIRED, $this->startReason($connection));
    }

    /**
     * With a stale limit of 0, undated metadata a refresh applied never
     * expires.
     *
     * @return void
     */
    public function testAStaleLimitOfZeroIsUnlimited(): void
    {
        config()->set('sso.metadata.stale_limit_seconds', 0);

        $connection = $this->saml();

        $this->refresher()->refreshDue();
        $this->clock->advance(86400 * 365);

        self::assertNull($this->startReason($connection));
    }

    /**
     * A connection of a protocol an application registered has no source, so a
     * queued refresh naming it is skipped.
     *
     * @return void
     */
    public function testAQueuedRefreshOfAProtocolWithNoSourceIsSkipped(): void
    {
        app(ProtocolManager::class)->extend('example', fn (): ExampleDriver => new ExampleDriver);

        $connection = $this->makeConnection(['protocol' => 'example']);

        self::assertSame(RefreshOutcome::SKIPPED, $this->refresher()->refreshQueued($connection->id)->outcome);
        self::assertSame([], $this->fetcher->requests());
    }

    /**
     * Why the driver refuses a start through the connection, if it does.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \LogicException
     */
    private function startReason(Connection $connection): ?FailureReason
    {
        $reference = RequestReference::fromString('Sq8tVv3w0kLmNoPqRsTuVwXyZ0123456');

        try {
            return app(Saml2Driver::class)->start($this->row($connection), new StartRequest(Purpose::SIGN_IN, 'web', $reference, new Secret('state')))->reason;
        } catch (RandomException $exception) {
            throw new \LogicException('The system has no randomness.', 0, $exception);
        }
    }

    /**
     * The outcome, connection, changed settings, metadata version and trust
     * change of each result.
     *
     * @param  list<\SineMacula\Laravel\Sso\Metadata\RefreshResult>  $results
     * @return list<list<mixed>>
     */
    private static function summaries(array $results): array
    {
        return array_map(
            static fn (RefreshResult $result): array => [$result->outcome, $result->connectionId, $result->changedSettings, $result->metadataVersion, $result->trustChanged],
            $results,
        );
    }

    /**
     * The connection's metadata version, failures in a row, next refresh, claim
     * and claim token, as stored.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $row
     * @return list<mixed>
     */
    private static function refreshState(Connection $row): array
    {
        return [
            $row->metadata_version,
            $row->metadata_refresh_failures,
            $row->metadata_refresh_at?->toIso8601String(),
            $row->metadata_claimed_until?->toIso8601String(),
            $row->metadata_claim_token,
        ];
    }

    /**
     * The level, message and context of each log record, in order.
     *
     * @param  list<array{channel: string, level: string, message: string, context: array<array-key, mixed>}>  $records
     * @return list<array{level: string, message: string, context: array<array-key, mixed>}>
     */
    private static function messages(array $records): array
    {
        return array_map(static fn (array $record): array => ['level' => $record['level'], 'message' => $record['message'], 'context' => $record['context']], $records);
    }

    /**
     * A refreshing SAML connection of the tenant, trusting the provider's
     * certificate, with the settings and attributes given; a setting given as
     * `null` is left out.
     *
     * @param  array<string, mixed>  $settings
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(array $settings = [], array $attributes = []): Connection
    {
        $values = array_filter([
            'idp_entity_id'    => FakeSamlIdentityProvider::ENTITY_ID,
            'sso_url'          => FakeSamlIdentityProvider::SSO_URL,
            'sso_binding'      => 'http_redirect',
            'metadata_url'     => self::URL,
            'metadata_refresh' => true,
            ...$settings,
        ], static fn (mixed $value): bool => $value !== null);

        $connection = $this->makeConnection(['protocol' => 'saml2', 'enabled' => true, 'settings' => $values, ...$attributes]);

        $this->trust($connection, self::idp()->certificate());

        return $connection;
    }

    /**
     * Trust the certificate for the connection and the use.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $certificate
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return void
     */
    private function trust(Connection $connection, string $certificate, KeyUse $use = KeyUse::IDP_SIGNING): void
    {
        $masked = MaskedKey::fromCertificate($certificate);

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => $use,
            'state'         => null,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $masked->certificate,
            'public_key'    => $masked->publicKey,
            'private_key'   => null,
            'fingerprint'   => $masked->fingerprint,
        ])->save();
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
     * The connection as stored now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function row(Connection $connection): Connection
    {
        return Connection::query()->findOrFail($connection->id);
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
     * The provider's unsigned metadata, naming the single sign-on URL given.
     *
     * @param  string  $ssoUrl
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata
     */
    private static function metadata(string $ssoUrl = FakeSamlIdentityProvider::SSO_URL): FakeSamlMetadata
    {
        return self::idp()->metadata($ssoUrl);
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
     * The administrator who asks for a refresh now.
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
        return require dirname(__DIR__, 3) . self::RATE_LIMITS_MIGRATION;
    }
}
