<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\MetadataRefreshFailed;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\MetadataApplier;
use SineMacula\Laravel\Sso\Metadata\MetadataExpiry;
use SineMacula\Laravel\Sso\Metadata\RefreshResult;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for writing what a metadata refresh found (SSO-2.8, SSO-2.13):
 * certificates replaced exactly, never as a union; an additive certificate
 * voiding nothing and leaving the trust version alone; a removal, a replacement
 * or an endpoint change voiding the flows in flight and raising the trust
 * version once; the entity id, subject settings and mapping never written; the
 * refresh's version, fetch, expiry and next refresh written, the failures reset
 * and the claim released; another entity, an endpoint that is not a valid
 * setting, metadata expired at commit and too many certificates refused as
 * failures; a change of the versions or the anchors made while the refresh
 * fetched refused as a conflict that writes nothing; and the backoff of
 * failures in a row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-import-type MetadataValues from \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata
 */
#[CoversClass(MetadataApplier::class)]
#[CoversClass(RefreshResult::class)]
final class MetadataApplierTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The provider's entity id. */
    private const string ENTITY_ID = 'https://idp.example.test/saml';

    /** @var string The provider's single sign-on URL. */
    private const string SSO_URL = 'https://idp.example.test/saml/sso';

    /** @var string The single sign-on URL the provider moves to. */
    private const string MOVED_URL = 'https://login.example.test/saml/sso';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection refreshed. */
    private Connection $connection;

    /**
     * Bind a fixed clock, switch SAML and the refresh on, create the tables and
     * a refreshing SAML connection trusting one certificate, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $this->clock);

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.metadata_refresh', true);

        $this->createConnectionTables();
        $this->createFlowTables();

        $this->connection = $this->makeConnection([
            'protocol' => 'saml2',
            'enabled'  => true,
            'settings' => [
                'idp_entity_id'    => self::ENTITY_ID,
                'sso_url'          => self::SSO_URL,
                'sso_binding'      => 'http_redirect',
                'subject_source'   => 'name_id',
                'name_id_format'   => 'email',
                'metadata_url'     => 'https://idp.example.test/metadata.xml',
                'metadata_refresh' => true,
            ],
            'attribute_mapping' => ['email' => 'mail'],
        ]);

        $this->trust(Certificates::distinct(0));

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
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A certificate added beside the one trusted is trusted, and voids nothing:
     * the trust version is kept and the flows in flight go on.
     *
     * @return void
     */
    public function testAnAdditiveCertificateVoidsNothing(): void
    {
        [$request, $code] = $this->inFlight();

        $result = $this->apply(self::metadata([0, 1]));

        self::assertSame(
            [RefreshOutcome::REFRESHED, ['idp_signing_certificates'], 1, false],
            [$result->outcome, $result->changedSettings, $result->metadataVersion, $result->trustChanged],
        );
        self::assertSame(self::sortedFingerprints([0, 1]), $this->trusted());
        self::assertSame(0, $this->row()->trust_version);
        self::assertNull($request->refresh()->voided_at);
        self::assertNull($code->refresh()->voided_at);
    }

    /**
     * Rows of `[trusted, published]`: the certificates trusted, and those the
     * metadata publishes, one or more removed.
     *
     * @return iterable<string, array{0: list<int>, 1: list<int>}>
     */
    public static function provideRemovals(): iterable
    {
        yield from [
            'one removed'               => [[0, 1], [0]],
            'one replaced'              => [[0], [1]],
            'two removed and one added' => [[0, 1, 2], [3]],
        ];
    }

    /**
     * A certificate no longer published is distrusted: exactly what the
     * metadata publishes is trusted, the flows in flight are voided and the
     * trust version is raised once.
     *
     * @param  list<int>  $trusted
     * @param  list<int>  $published
     * @return void
     */
    #[DataProvider('provideRemovals')]
    public function testARemovedCertificateVoidsAndRaisesTheTrustVersionOnce(array $trusted, array $published): void
    {
        foreach (array_diff($trusted, [0]) as $index) {
            $this->trust(Certificates::distinct($index));
        }

        [$request, $code] = $this->inFlight();

        $result = $this->apply(self::metadata($published));

        self::assertSame([['idp_signing_certificates'], true], [$result->changedSettings, $result->trustChanged]);
        self::assertSame(self::sortedFingerprints($published), $this->trusted());
        self::assertSame(1, $this->row()->trust_version);
        self::assertSame('2026-11-01T09:30:00+00:00', $request->refresh()->voided_at?->toIso8601String());
        self::assertSame('2026-11-01T09:30:00+00:00', $code->refresh()->voided_at?->toIso8601String());
    }

    /**
     * Rows of `[changes, published, changed]`: the endpoint the metadata names,
     * the certificates it publishes, and the settings the refresh reports
     * changed.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: list<int>, 2: list<string>}>
     */
    public static function provideEndpointChanges(): iterable
    {
        yield from [
            'the URL'                          => [['sso_url' => self::MOVED_URL], [0], ['sso_url']],
            'the binding'                      => [['sso_binding' => 'http_post'], [0], ['sso_binding']],
            'both'                             => [['sso_url' => self::MOVED_URL, 'sso_binding' => 'http_post'], [0], ['sso_url', 'sso_binding']],
            'both, and a certificate replaced' => [
                ['sso_url' => self::MOVED_URL, 'sso_binding' => 'http_post'],
                [1],
                ['sso_url', 'sso_binding', 'idp_signing_certificates'],
            ],
        ];
    }

    /**
     * A changed single sign-on endpoint is written and is a trust change: the
     * flows in flight are voided and the trust version raised once, with any
     * certificate removed.
     *
     * @param  array<string, mixed>  $changes
     * @param  list<int>  $published
     * @param  list<string>  $changed
     * @return void
     */
    #[DataProvider('provideEndpointChanges')]
    public function testAnEndpointChangeIsWrittenAndVoids(array $changes, array $published, array $changed): void
    {
        [$request] = $this->inFlight();

        $result = $this->apply(self::metadata($published, $changes));
        $row    = $this->row();

        self::assertSame([$changed, true], [$result->changedSettings, $result->trustChanged]);
        self::assertSame($changes['sso_url'] ?? self::SSO_URL, $row->settings['sso_url']);
        self::assertSame($changes['sso_binding'] ?? 'http_redirect', $row->settings['sso_binding']);
        self::assertSame(1, $row->trust_version);
        self::assertNotNull($request->refresh()->voided_at);
    }

    /**
     * Metadata that changes nothing writes only the refresh: no setting, no
     * certificate, no void.
     *
     * @return void
     */
    public function testMetadataThatChangesNothingWritesOnlyTheRefresh(): void
    {
        [$request] = $this->inFlight();

        $result = $this->apply(self::metadata([0]));

        self::assertSame(
            [RefreshOutcome::REFRESHED, [], 1, false, null],
            [$result->outcome, $result->changedSettings, $result->metadataVersion, $result->trustChanged, $result->reason],
        );
        self::assertSame([0, 1], [$this->row()->trust_version, $this->row()->metadata_version]);
        self::assertNull($request->refresh()->voided_at);
    }

    /**
     * Rows of `[valid until, next refresh]`: the metadata's expiry, and when
     * the next refresh is due: after the interval, never after the expiry.
     *
     * @return iterable<string, array{0: ?string, 1: string}>
     */
    public static function provideNextRefreshes(): iterable
    {
        yield from [
            'undated'                              => [null, '2026-11-02T09:30:00+00:00'],
            'expiring a second after the interval' => ['2026-11-02T09:30:01+00:00', '2026-11-02T09:30:00+00:00'],
            'expiring as the interval ends'        => ['2026-11-02T09:30:00+00:00', '2026-11-02T09:30:00+00:00'],
            'expiring a second before it ends'     => ['2026-11-02T09:29:59+00:00', '2026-11-02T09:29:59+00:00'],
            'expiring in an hour'                  => ['2026-11-01T10:30:00+00:00', '2026-11-01T10:30:00+00:00'],
        ];
    }

    /**
     * A refresh raises the metadata version, records the fetch and the expiry,
     * resets the failures, releases the claim, and is next due after the
     * interval or at the expiry, whichever comes first.
     *
     * @param  ?string  $validUntil
     * @param  string  $next
     * @return void
     */
    #[DataProvider('provideNextRefreshes')]
    public function testWritesTheRefresh(?string $validUntil, string $next): void
    {
        $this->connection->forceFill([
            'metadata_version'          => 4,
            'metadata_refresh_failures' => 3,
            'metadata_claimed_until'    => $this->clock->now()->addMinutes(5),
        ])->save();

        $this->apply(self::metadata([0], ['valid_until' => $validUntil === null ? null : CarbonImmutable::parse($validUntil)]));

        $row = $this->row();

        self::assertSame(
            [5, '2026-11-01T09:30:00+00:00', $validUntil, $next, 0, null],
            [
                $row->metadata_version,
                $row->metadata_fetched_at?->toIso8601String(),
                $row->metadata_valid_until?->toIso8601String(),
                $row->metadata_refresh_at?->toIso8601String(),
                $row->metadata_refresh_failures,
                $row->metadata_claimed_until,
            ],
        );
    }

    /**
     * A refresh never writes the entity id, the subject settings, any other
     * setting or the attribute mapping.
     *
     * @return void
     */
    public function testNeverWritesTheEntityIdSubjectSettingsOrMapping(): void
    {
        $before = $this->row()->settings;

        $this->apply(self::metadata([1], ['sso_url' => self::MOVED_URL, 'name_id_formats' => ['urn:oasis:names:tc:SAML:2.0:nameid-format:persistent']]));

        $row = $this->row();

        self::assertSame(self::sortedByKey([...$before, 'sso_url' => self::MOVED_URL]), self::sortedByKey($row->settings));
        self::assertSame(['email' => 'mail'], $row->attribute_mapping);
    }

    /**
     * Rows of `[changes, published, reason]`: metadata a refresh may not apply,
     * and the reason its failure is recorded with.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: list<int>, 2: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideRefusals(): iterable
    {
        yield from [
            'another entity'                => [['entity_id' => 'https://other.example.test/saml'], [1], FailureReason::METADATA_INVALID],
            'a URL over HTTP'               => [['sso_url' => 'http://idp.example.test/saml/sso'], [1], FailureReason::METADATA_INVALID],
            'an unknown binding'            => [['sso_binding' => 'http_artifact'], [1], FailureReason::METADATA_INVALID],
            'expired at commit'             => [['valid_until' => CarbonImmutable::parse('2026-11-01T09:30:00Z')], [1], FailureReason::METADATA_EXPIRED],
            'expired a second before'       => [['valid_until' => CarbonImmutable::parse('2026-11-01T09:29:59Z')], [1], FailureReason::METADATA_EXPIRED],
            'too many certificates'         => [[], range(1, 11), FailureReason::METADATA_INVALID],
            'an elliptic curve certificate' => [
                ['signing_certificates' => [['certificate' => Certificates::ecP256(), 'fingerprint' => 'ec']]],
                [],
                FailureReason::METADATA_INVALID,
            ],
        ];
    }

    /**
     * Metadata that may not be applied records a failure: nothing it holds is
     * written, the failure is counted, the next refresh backs off and the claim
     * is released.
     *
     * @param  array<string, mixed>  $changes
     * @param  list<int>  $published
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testMetadataThatMayNotBeAppliedRecordsAFailure(array $changes, array $published, FailureReason $reason): void
    {
        $this->connection->forceFill(['metadata_claimed_until' => $this->clock->now()->addMinutes(5)])->save();

        $before = $this->row()->settings;
        $result = $this->apply(self::metadata($published, $changes));
        $row    = $this->row();

        self::assertSame(
            [RefreshOutcome::FAILED, $reason, 1, '2026-11-01T09:35:00+00:00'],
            [$result->outcome, $result->reason, $result->failures, $result->nextAttemptAt?->toIso8601String()],
        );
        self::assertSame([self::fingerprint(0)], $this->trusted());
        self::assertSame([self::sortedByKey($before), 0, 0, 1, '2026-11-01T09:35:00+00:00', null], [
            self::sortedByKey($row->settings),
            $row->metadata_version,
            $row->trust_version,
            $row->metadata_refresh_failures,
            $row->metadata_refresh_at?->toIso8601String(),
            $row->metadata_claimed_until,
        ]);
    }

    /**
     * Metadata expiring a second after the commit is applied.
     *
     * @return void
     */
    public function testMetadataExpiringAfterTheCommitIsApplied(): void
    {
        $result = $this->apply(self::metadata([0], ['valid_until' => CarbonImmutable::parse('2026-11-01T09:30:01Z')]));

        self::assertTrue($result->isRefreshed());
        self::assertSame('2026-11-01T09:30:01+00:00', $this->row()->metadata_refresh_at?->toIso8601String());
    }

    /**
     * Rows of `[change]`: a change made while the refresh fetched.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideConflicts(): iterable
    {
        yield from [
            'another refresh wrote' => ['metadata_version'],
            'the trust changed'     => ['trust_version'],
            'an anchor added'       => ['anchor_added'],
            'an anchor removed'     => ['anchor_removed'],
        ];
    }

    /**
     * A change of the metadata version, the trust version or the anchors made
     * while the refresh fetched refuses it as a conflict that writes nothing,
     * reported with the connection as the change left it.
     *
     * @param  string  $change
     * @return void
     */
    #[DataProvider('provideConflicts')]
    public function testAChangeMadeWhileFetchingIsAConflictThatWritesNothing(string $change): void
    {
        $anchor = Certificates::distinct(8);

        $this->connection->forceFill(['metadata_refresh_failures' => 2, 'metadata_refresh_at' => $this->clock->now()->addMinutes(10)])->save();

        if ($change === 'anchor_removed') {
            $this->trust($anchor, KeyUse::METADATA_SIGNING);
        }

        $claimed = $this->row();
        $anchors = $change === 'anchor_removed' ? [self::fingerprintOf($anchor)] : [];

        if ($change === 'anchor_added') {
            $this->trust($anchor, KeyUse::METADATA_SIGNING);
        } elseif ($change === 'anchor_removed') {
            ConnectionKey::query()->where('use', KeyUse::METADATA_SIGNING->value)->delete();
        } else {
            $this->connection->forceFill([$change => 7])->save();
        }

        $before = $this->row()->getAttributes();

        $this->startRecordingEvents();

        $result = $this->applier()->apply($claimed, $anchors, self::metadata([1], ['sso_url' => self::MOVED_URL]));

        self::assertSame([RefreshOutcome::CONFLICT, FailureReason::METADATA_CONFLICT, []], [$result->outcome, $result->reason, $result->changedSettings]);
        self::assertSame($before, $this->row()->getAttributes());
        self::assertSame([self::fingerprint(0)], $this->trusted());

        $this->assertEventSequence([MetadataRefreshFailed::class]);

        $failed = $this->recordedEvents()[0];

        self::assertInstanceOf(MetadataRefreshFailed::class, $failed);
        self::assertSame([FailureReason::METADATA_CONFLICT, 2, '2026-11-01T09:40:00+00:00'], [$failed->reason, $failed->failures, $failed->nextAttemptAt?->toIso8601String()]);
    }

    /**
     * A connection deleted while the refresh fetched is a conflict reported by
     * no event, since nothing is left to report it of.
     *
     * @return void
     */
    public function testAConnectionDeletedWhileFetchingIsAConflict(): void
    {
        $claimed = $this->row();

        ConnectionKey::query()->delete();
        Connection::query()->delete();

        self::assertSame(RefreshOutcome::CONFLICT, $this->applier()->apply($claimed, [], self::metadata([0]))->outcome);
        self::assertSame(RefreshOutcome::CONFLICT, $this->applier()->fail($claimed, FailureReason::FETCH_FAILED)->outcome);

        $this->assertNoEvents();
    }

    /**
     * Failures in a row back off from 5 minutes, doubling, up to 6 hours, and a
     * success resets them.
     *
     * @return void
     */
    public function testFailuresInARowBackOffAndASuccessResetsThem(): void
    {
        $claimed = $this->row();
        $waits   = [];

        foreach (range(1, 9) as $failure) {

            $result  = $this->applier()->fail($claimed, FailureReason::FETCH_FAILED);
            $waits[] = [$result->failures, (int) $this->clock->now()->diffInSeconds($result->nextAttemptAt)];

            self::assertSame(
                [$failure, $result->nextAttemptAt?->toIso8601String()],
                [$this->row()->metadata_refresh_failures, $this->row()->metadata_refresh_at?->toIso8601String()],
            );
        }

        self::assertSame([[1, 300], [2, 600], [3, 1200], [4, 2400], [5, 4800], [6, 9600], [7, 19200], [8, 21600], [9, 21600]], $waits);
        self::assertTrue($this->applier()->apply($this->row(), [], self::metadata([0]))->isRefreshed());
        self::assertSame(0, $this->row()->metadata_refresh_failures);
    }

    /**
     * A failure is not recorded over a refresh that wrote since the failed one
     * read the connection: it is a conflict, and the winner's state stands.
     *
     * @return void
     */
    public function testAFailureIsNotRecordedOverAnotherRefresh(): void
    {
        $claimed = $this->row();

        $this->connection->forceFill(['metadata_version' => 1])->save();

        $result = $this->applier()->fail($claimed, FailureReason::FETCH_FAILED, new ActingIdentity('App\Models\User', '42'));

        self::assertSame([RefreshOutcome::CONFLICT, FailureReason::METADATA_CONFLICT], [$result->outcome, $result->reason]);
        self::assertSame([0, null], [$this->row()->metadata_refresh_failures, $this->row()->metadata_refresh_at]);
    }

    /**
     * What a refresh applied expires the stale limit after it, or at its
     * `validUntil` when that comes first.
     *
     * @return void
     */
    public function testWhatARefreshAppliedExpires(): void
    {
        $this->apply(self::metadata([0]));

        $stale = app(MetadataExpiry::class)->expiresAt($this->row());

        $this->apply(self::metadata([0], ['valid_until' => CarbonImmutable::parse('2026-11-05T00:00:00Z')]));

        $dated = app(MetadataExpiry::class)->expiresAt($this->row());

        self::assertSame(['2026-12-01T09:30:00+00:00', '2026-11-05T00:00:00+00:00'], [$stale?->toIso8601String(), $dated?->toIso8601String()]);
    }

    /**
     * A result encodes its outcome, its reason and its values, with snake_case
     * keys and the time in UTC.
     *
     * @return void
     */
    public function testAResultEncodesItsValues(): void
    {
        $failed = RefreshResult::failed('c1', FailureReason::FETCH_FAILED, 2, CarbonImmutable::parse('2026-11-01T11:00:00+01:00'));

        self::assertSame([
            'outcome'          => 'failed',
            'connection_id'    => 'c1',
            'reason'           => 'fetch_failed',
            'changed_settings' => [],
            'metadata_version' => null,
            'trust_changed'    => false,
            'failures'         => 2,
            'next_attempt_at'  => '2026-11-01T10:00:00+00:00',
        ], $failed->jsonSerialize());
        self::assertSame([
            'outcome'          => 'refreshed',
            'connection_id'    => 'c1',
            'reason'           => null,
            'changed_settings' => ['sso_url'],
            'metadata_version' => 3,
            'trust_changed'    => true,
            'failures'         => null,
            'next_attempt_at'  => null,
        ], RefreshResult::refreshed('c1', ['sso_url'], 3, true)->jsonSerialize());
        self::assertSame(
            [['in_progress', 'metadata_refresh_in_progress'], ['skipped', null], ['refused', 'connection_not_found'], ['conflict', 'metadata_conflict']],
            array_map(
                static fn (RefreshResult $result): array => [$result->outcome->value, $result->reason?->value],
                [RefreshResult::inProgress('c1'), RefreshResult::skipped('c1'), RefreshResult::refused(FailureReason::CONNECTION_NOT_FOUND), RefreshResult::conflict('c1')],
            ),
        );
        self::assertNull(RefreshResult::refused(FailureReason::CONNECTION_NOT_FOUND)->connectionId);
    }

    /**
     * Apply the metadata to the connection as it is now, with no anchor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata  $metadata
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     */
    private function apply(IdpMetadata $metadata): RefreshResult
    {
        return $this->applier()->apply($this->row(), [], $metadata);
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
     * The connection as stored now.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function row(): Connection
    {
        return Connection::query()->findOrFail($this->connection->id);
    }

    /**
     * A request and a handoff code in flight through the connection.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Models\AuthorizationRequest, 1: \SineMacula\Laravel\Sso\Models\HandoffCode}
     */
    private function inFlight(): array
    {
        return [$this->makeAuthorizationRequest($this->connection), $this->makeHandoffCode($this->connection)];
    }

    /**
     * Trust the certificate for the connection and the use.
     *
     * @param  string  $certificate
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return void
     */
    private function trust(string $certificate, KeyUse $use = KeyUse::IDP_SIGNING): void
    {
        $masked = MaskedKey::fromCertificate($certificate);

        (new ConnectionKey)->forceFill([
            'connection_id' => $this->connection->id,
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
     * The fingerprints of the signing certificates the connection trusts,
     * sorted.
     *
     * @return list<string>
     */
    private function trusted(): array
    {
        $fingerprints = ConnectionKey::query()->where('use', KeyUse::IDP_SIGNING->value)->pluck('fingerprint')->all();

        sort($fingerprints);

        return array_map(strval(...), $fingerprints);
    }

    /**
     * The metadata of the provider's entity publishing the certificates of the
     * indices, with the changes given.
     *
     * @param  list<int>  $published
     * @param  array<string, mixed>  $changes
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata
     */
    private static function metadata(array $published, array $changes = []): IdpMetadata
    {
        $certificates = array_map(static fn (int $index): array => [
            'certificate' => (string) MaskedKey::fromCertificate(Certificates::distinct($index))->certificate,
            'fingerprint' => self::fingerprint($index),
        ], $published);

        /** @var MetadataValues $values */
        $values = [
            'entity_id'               => self::ENTITY_ID,
            'sso_url'                 => self::SSO_URL,
            'sso_binding'             => 'http_redirect',
            'signing_certificates'    => $certificates,
            'encryption_certificates' => [],
            'name_id_formats'         => [],
            'valid_until'             => null,
            ...$changes,
        ];

        return IdpMetadata::read($values);
    }

    /**
     * The fingerprint of the certificate of the index.
     *
     * @param  int  $index
     * @return string
     */
    private static function fingerprint(int $index): string
    {
        return self::fingerprintOf(Certificates::distinct($index));
    }

    /**
     * The fingerprint of the certificate.
     *
     * @param  string  $certificate
     * @return string
     */
    private static function fingerprintOf(string $certificate): string
    {
        return (string) MaskedKey::fromCertificate($certificate)->fingerprint;
    }

    /**
     * The fingerprints of the certificates of the indices, sorted.
     *
     * @param  list<int>  $indices
     * @return list<string>
     */
    private static function sortedFingerprints(array $indices): array
    {
        $fingerprints = array_map(self::fingerprint(...), $indices);

        sort($fingerprints);

        return $fingerprints;
    }

    /**
     * The map sorted by key, as a JSON column read back may order it any way.
     *
     * @param  array<string, mixed>  $map
     * @return array<string, mixed>
     */
    private static function sortedByKey(array $map): array
    {
        ksort($map);

        return $map;
    }
}
