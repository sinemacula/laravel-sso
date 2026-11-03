<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Illuminate\Database\Migrations\Migration;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\MetadataEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\KeyAdded;
use SineMacula\Laravel\Sso\Events\KeyRetired;
use SineMacula\Laravel\Sso\Events\MetadataRefreshed;
use SineMacula\Laravel\Sso\Events\MetadataRefreshFailed;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Pins the events of a metadata refresh (SSO-2.8, SSO-10.3 to SSO-10.5): a
 * refresh that adds a certificate reports `[KeyAdded, MetadataRefreshed]`;
 * one that replaces a certificate and moves the endpoint
 * `[KeyRetired, KeyAdded, ConnectionUpdated, MetadataRefreshed]`; one that
 * changes nothing `[MetadataRefreshed]` naming none; a failure or a conflict
 * `[MetadataRefreshFailed]`; a refresh that did not run nothing. Each names the
 * connection, its tenant and protocol, and the acting identity of the
 * administrator who asked, or none for a scheduled run; none carries a
 * certificate, a URL or the metadata.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataEvents::class)]
#[CoversClass(MetadataRefresher::class)]
final class MetadataEventSequenceTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var string The tenant whose connection refreshes. */
    private const string TENANT = 'tenant-1';

    /** @var string The URL the provider serves its metadata at. */
    private const string URL = 'https://idp.example.test/metadata.xml';

    /** @var string The single sign-on URL the provider moves to. */
    private const string MOVED_URL = 'https://login.example.test/saml/sso';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the refresh fetches through. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection refreshed. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Administration\ActingIdentity The administrator who asks. */
    private ActingIdentity $actor;

    /**
     * Bind a fixed clock and a fake fetcher, switch SAML and the refresh on,
     * create the tables (the rate limit counters' among them) and a refreshing
     * connection trusting the provider's certificate, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher = new FakeFetcher;
        $this->actor   = new ActingIdentity('App\Models\User', '42');

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Fetcher::class, $this->fetcher);

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.metadata_refresh', true);

        $this->createConnectionTables();
        $this->createFlowTables();
        self::rateLimitsMigration()->up(); // @phpstan-ignore method.notFound

        $this->connection = $this->makeConnection(['protocol' => 'saml2', 'enabled' => true, 'settings' => [
            'idp_entity_id'    => FakeSamlIdentityProvider::ENTITY_ID,
            'sso_url'          => FakeSamlIdentityProvider::SSO_URL,
            'sso_binding'      => 'http_redirect',
            'metadata_url'     => self::URL,
            'metadata_refresh' => true,
        ]]);

        $this->trust(self::idp()->certificate());
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
     * A scheduled refresh adding a certificate reports it added, then the
     * refresh naming the certificates, with no acting identity.
     *
     * @return void
     */
    public function testAScheduledAdditionReportsTheKeyThenTheRefresh(): void
    {
        $this->serve(self::metadata()->with(['signing_certificates' => [self::idp()->certificate(), Certificates::distinct(7)]]));

        $this->refresher()->refreshDue();

        $this->assertEventSequence([KeyAdded::class, MetadataRefreshed::class]);

        [$added, $refreshed] = $this->recordedEvents();

        self::assertInstanceOf(KeyAdded::class, $added);
        self::assertInstanceOf(MetadataRefreshed::class, $refreshed);
        self::assertSame([KeyUse::IDP_SIGNING, MaskedKey::fromCertificate(Certificates::distinct(7))->fingerprint], [$added->use, $added->fingerprint]);
        self::assertSame([['idp_signing_certificates'], 1, false], [$refreshed->changedSettings, $refreshed->metadataVersion, $refreshed->trustChanged]);

        $this->assertContexts(null);
    }

    /**
     * A refresh an administrator asked for that replaces a certificate and
     * moves the endpoint reports the retirement, the addition, the update and
     * the refresh, in that order, each with the administrator.
     *
     * @return void
     */
    public function testAReplacementAndAMovedEndpointReportEachChangeInOrder(): void
    {
        $this->serve(self::metadata(self::MOVED_URL)->with(['signing_certificates' => [Certificates::distinct(7)]]));

        $this->refresher()->refreshNow(self::TENANT, $this->connection->id, $this->actor);

        $this->assertEventSequence([KeyRetired::class, KeyAdded::class, ConnectionUpdated::class, MetadataRefreshed::class]);

        [$retired, , $updated, $refreshed] = $this->recordedEvents();

        self::assertInstanceOf(KeyRetired::class, $retired);
        self::assertInstanceOf(ConnectionUpdated::class, $updated);
        self::assertInstanceOf(MetadataRefreshed::class, $refreshed);
        self::assertSame(MaskedKey::fromCertificate(self::idp()->certificate())->fingerprint, $retired->fingerprint);
        self::assertSame(['sso_url'], $updated->changedSettings);
        self::assertSame([['sso_url', 'idp_signing_certificates'], 1, true], [$refreshed->changedSettings, $refreshed->metadataVersion, $refreshed->trustChanged]);

        $this->assertContexts('42');
    }

    /**
     * A refresh that changes nothing reports the refresh alone, naming none.
     *
     * @return void
     */
    public function testARefreshThatChangesNothingReportsTheRefreshAlone(): void
    {
        $this->serve(self::metadata());

        $this->refresher()->refreshDue();

        $this->assertEventSequence([MetadataRefreshed::class]);

        $refreshed = $this->recordedEvents()[0];

        self::assertInstanceOf(MetadataRefreshed::class, $refreshed);
        self::assertSame([[], 1, false], [$refreshed->changedSettings, $refreshed->metadataVersion, $refreshed->trustChanged]);
    }

    /**
     * A failed refresh reports one failure, with its reason, the failures in a
     * row and the next attempt.
     *
     * @return void
     */
    public function testAFailureReportsOneFailure(): void
    {
        $this->fetcher->respond(self::URL, FetchResult::failed());

        $this->refresher()->refreshNow(self::TENANT, $this->connection->id, $this->actor);

        $this->assertEventSequence([MetadataRefreshFailed::class]);

        $failed = $this->recordedEvents()[0];

        self::assertInstanceOf(MetadataRefreshFailed::class, $failed);
        self::assertSame([FailureReason::FETCH_FAILED, 1, '2026-11-01T09:35:00+00:00'], [$failed->reason, $failed->failures, $failed->nextAttemptAt?->toIso8601String()]);

        $this->assertContexts('42');
    }

    /**
     * A refresh that lost to a trust change made while it fetched reports one
     * failure, a conflict, and nothing of the change it did not make.
     *
     * @return void
     */
    public function testAConflictReportsOneFailure(): void
    {
        $id  = $this->connection->id;
        $xml = self::metadata(self::MOVED_URL)->toXml();

        $this->fetcher->respond(self::URL, static function (FetchRequest $request) use ($id, $xml): FetchResult {
            unset($request);

            Connection::query()->whereKey($id)->increment('trust_version');

            return FetchResult::fetched(200, [], $xml);
        });

        $this->refresher()->refreshDue();

        $this->assertEventSequence([MetadataRefreshFailed::class]);

        $failed = $this->recordedEvents()[0];

        self::assertInstanceOf(MetadataRefreshFailed::class, $failed);
        self::assertSame([FailureReason::METADATA_CONFLICT, 0, null], [$failed->reason, $failed->failures, $failed->nextAttemptAt]);
    }

    /**
     * A refresh that did not run reports nothing: one another server is
     * running, and one refused.
     *
     * @return void
     */
    public function testARefreshThatDidNotRunReportsNothing(): void
    {
        Connection::query()->whereKey($this->connection->id)->update(['metadata_claimed_until' => '2026-11-01 09:31:00']);

        $this->refresher()->refreshNow(self::TENANT, $this->connection->id, $this->actor);
        $this->refresher()->refreshNow('tenant-2', $this->connection->id, $this->actor);

        $this->assertNoEvents();
    }

    /**
     * No event of a refresh, a failure or a conflict carries a certificate, a
     * URL, the entity id or anything else of the metadata.
     *
     * @return void
     */
    public function testNoEventCarriesACertificateAUrlOrTheMetadata(): void
    {
        $added    = Certificates::distinct(7);
        $metadata = self::metadata(self::MOVED_URL)->with(['signing_certificates' => [$added], 'name_id_formats' => ['urn:example:secret-format']]);

        $this->serve($metadata);
        $this->refresher()->refreshNow(self::TENANT, $this->connection->id, $this->actor);

        $this->fetcher->respond(self::URL, FetchResult::fetched(500, [], 'internal detail of the provider'));
        $this->refresher()->refreshNow(self::TENANT, $this->connection->id, $this->actor);

        $events = array_map(static fn (SsoEvent $event): string => serialize($event) . json_encode($event), $this->recordedEvents());

        self::assertCount(5, $events);

        foreach ($events as $event) {
            foreach ([self::URL, self::MOVED_URL, FakeSamlIdentityProvider::ENTITY_ID, 'idp.example.test', 'urn:example:secret-format', 'internal detail'] as $value) {
                self::assertStringNotContainsString($value, $event);
            }

            foreach ([$added, self::idp()->certificate()] as $certificate) {
                self::assertStringNotContainsString(substr((string) preg_replace('/-----[^-]+-----|\s+/', '', $certificate), 40, 64), $event);
            }
        }
    }

    /**
     * Assert every event recorded names the connection, its tenant and
     * protocol, and the acting identity given.
     *
     * @param  ?string  $actingIdentityId
     * @return void
     */
    private function assertContexts(?string $actingIdentityId): void
    {
        foreach ($this->recordedEvents() as $event) {

            $context = $event->context();

            self::assertSame(
                [$this->connection->id, self::TENANT, 'saml2', $actingIdentityId, $actingIdentityId === null ? null : 'App\Models\User', null],
                [
                    $context->connectionId,
                    $context->connectionTenantId,
                    $context->protocol,
                    $context->actingIdentityId,
                    $context->actingIdentityMorphClass,
                    $context->requestReference,
                ],
            );
        }
    }

    /**
     * Trust the certificate for the connection.
     *
     * @param  string  $certificate
     * @return void
     */
    private function trust(string $certificate): void
    {
        $masked = MaskedKey::fromCertificate($certificate);

        (new ConnectionKey)->forceFill([
            'connection_id' => $this->connection->id,
            'use'           => KeyUse::IDP_SIGNING,
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
     * The shipped migration of the rate limit counters.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function rateLimitsMigration(): Migration
    {
        return require dirname(__DIR__, 3) . self::RATE_LIMITS_MIGRATION;
    }
}
