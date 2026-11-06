<?php

declare(strict_types = 1);

namespace Tests\Integration\Metadata;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\MetadataEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\KeyAdded;
use SineMacula\Laravel\Sso\Events\KeyRetired;
use SineMacula\Laravel\Sso\Events\MetadataRefreshed;
use SineMacula\Laravel\Sso\Events\MetadataRefreshFailed;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Metadata\MetadataApplier;
use SineMacula\Laravel\Sso\Metadata\RefreshClaim;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Integration tests of when a metadata refresh's events reach their listeners
 * (SSO-10.5): a refresh or a failure written inside an outer transaction on the
 * storage connection that rolls back writes and reports nothing; one that
 * commits reports only once the outer transaction commits, in order; and each
 * event crosses a queue with its values intact.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataEvents::class)]
#[CoversClass(MetadataApplier::class)]
final class MetadataEventsAfterCommitTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /** @var string The provider's entity id. */
    private const string ENTITY_ID = 'https://idp.example.test/saml';

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection refreshed. */
    private Connection $connection;

    /**
     * Bind a fixed clock, switch SAML and the refresh on, create the tables and
     * a refreshing connection trusting one certificate, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.metadata_refresh', true);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => 'saml2', 'enabled' => true, 'settings' => [
            'idp_entity_id'    => self::ENTITY_ID,
            'sso_url'          => 'https://idp.example.test/saml/sso',
            'sso_binding'      => 'http_redirect',
            'metadata_url'     => 'https://idp.example.test/metadata.xml',
            'metadata_refresh' => true,
        ]]);

        $masked = MaskedKey::fromCertificate(Certificates::distinct(0));

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

        $this->startRecordingEvents();
    }

    /**
     * A refresh and a failure written inside an outer transaction that rolls
     * back write nothing and report nothing, though each succeeded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshOrFailureRolledBackWritesAndReportsNothing(): void
    {
        $before = $this->rows();

        try {
            DB::connection(StorageConnection::name())->transaction(function (): void {
                self::assertTrue($this->applier()->apply($this->claim(), self::replacement(), self::now(), Clients::browser())->isRefreshed());
                self::assertSame(1, $this->applier()->fail($this->claim(), FailureReason::FETCH_FAILED, Clients::browser())->failures);

                throw new \RuntimeException('Rolled back.');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('Rolled back.', $exception->getMessage());
        }

        self::assertSame($before, $this->rows());

        $this->assertNoEvents();
    }

    /**
     * A refresh written inside an outer transaction that commits reports
     * nothing until it commits, then every event in order.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshCommittedReportsOnlyOnceTheTransactionCommits(): void
    {
        DB::connection(StorageConnection::name())->transaction(function (): void {
            $this->applier()->apply($this->claim(), self::replacement(), self::now(), Clients::browser(), new ActingIdentity('App\Models\User', '42'));

            $this->assertNoEvents();
        });

        $this->assertEventSequence([KeyRetired::class, KeyAdded::class, MetadataRefreshed::class]);
    }

    /**
     * Events dispatched outside any transaction reach listeners at once.
     *
     * @return void
     */
    public function testEventsOutsideATransactionAreDispatchedAtOnce(): void
    {
        app(MetadataEvents::class)->refreshFailed($this->row(), FailureReason::FETCH_REFUSED, 3, null, null, Clients::browser());

        $this->assertEventSequence([MetadataRefreshFailed::class]);
    }

    /**
     * Each event crosses a queue as it is, its values intact.
     *
     * @return void
     */
    public function testEachEventCrossesAQueueIntact(): void
    {
        $this->applier()->apply($this->claim(), self::replacement(), self::now(), Clients::browser());
        $this->applier()->fail($this->claim(), FailureReason::METADATA_INVALID, Clients::browser());

        $events = $this->recordedEvents();

        self::assertCount(4, $events);

        foreach ($events as $event) {
            self::assertEquals($event, unserialize(serialize($event)));
        }

        $refreshed = $events[2];
        $failed    = $events[3];

        self::assertInstanceOf(MetadataRefreshed::class, $refreshed);
        self::assertInstanceOf(MetadataRefreshFailed::class, $failed);
        self::assertSame([['idp_signing_certificates'], 1, true], [$refreshed->changedSettings, $refreshed->metadataVersion, $refreshed->trustChanged]);
        self::assertSame([FailureReason::METADATA_INVALID, 1, '2026-11-01T09:35:00+00:00'], [$failed->reason, $failed->failures, $failed->nextAttemptAt?->toIso8601String()]);
    }

    /**
     * The applier, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\MetadataApplier
     */
    private function applier(): MetadataApplier
    {
        return app(MetadataApplier::class);
    }

    /**
     * Claim the connection as it is now, as the refresher does: a fresh token
     * written, and the connection, its trusted certificates and its anchors as
     * they are, the snapshot.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshClaim
     */
    private function claim(): RefreshClaim
    {
        $row     = $this->row();
        $keys    = app(KeyRing::class);
        $trusted = RefreshClaim::trustedOf($keys->trustedCertificates($row->id), $keys->trustedCertificates($row->id, KeyUse::METADATA_SIGNING));
        $token   = hash('md5', uniqid('claim', true));

        Connection::query()->whereKey($row->id)->update(['metadata_claim_token' => $token]);

        return new RefreshClaim($row, $token, $trusted);
    }

    /**
     * The clock's now, the moment the metadata was validated.
     *
     * @return \Carbon\CarbonImmutable
     */
    private static function now(): CarbonImmutable
    {
        return app(Clock::class)->now();
    }

    /**
     * The connection as stored now.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function row(): Connection
    {
        return Connection::query()->findOrFail($this->connection->id);
    }

    /**
     * Every row of the connections and keys tables, as stored.
     *
     * @return array{connections: list<array<string, mixed>>, keys: list<array<string, mixed>>}
     */
    private function rows(): array
    {
        return [
            'connections' => array_values(Connection::query()->orderBy('id')->get()->map(static fn (Connection $row): array => $row->getAttributes())->all()),
            'keys'        => array_values(ConnectionKey::query()->orderBy('id')->get()->map(static fn (ConnectionKey $row): array => $row->getAttributes())->all()),
        ];
    }

    /**
     * Metadata of the entity publishing another certificate in place of the one
     * trusted.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata
     */
    private static function replacement(): IdpMetadata
    {
        $masked = MaskedKey::fromCertificate(Certificates::distinct(1));

        return IdpMetadata::read([
            'entity_id'               => self::ENTITY_ID,
            'sso_url'                 => 'https://idp.example.test/saml/sso',
            'sso_binding'             => 'http_redirect',
            'signing_certificates'    => [['certificate' => (string) $masked->certificate, 'fingerprint' => (string) $masked->fingerprint]],
            'encryption_certificates' => [],
            'name_id_formats'         => [],
            'valid_until'             => null,
        ]);
    }
}
