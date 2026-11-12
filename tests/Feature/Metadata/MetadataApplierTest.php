<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\MetadataRefreshed;
use SineMacula\Laravel\Sso\Events\MetadataRefreshFailed;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\MetadataApplier;
use SineMacula\Laravel\Sso\Metadata\MetadataExpiry;
use SineMacula\Laravel\Sso\Metadata\RefreshClaim;
use SineMacula\Laravel\Sso\Metadata\RefreshResult;
use SineMacula\Laravel\Sso\Metadata\RefreshWriter;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for writing what a SAML metadata refresh found.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-import-type MetadataValues from \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata
 */
#[CoversClass(MetadataApplier::class)]
#[CoversClass(RefreshWriter::class)]
#[CoversClass(RefreshResult::class)]
#[CoversClass(RefreshClaim::class)]
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
     * Bind a fixed clock, enable SAML and refresh, create a refreshing
     * connection trusting one certificate, and record events.
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

        $this->usePackageTables();

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
     * A certificate no longer published is distrusted, voiding the flows in
     * flight and raising the trust version once.
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
     * Rows of `[changes, published, changed]`: the endpoint, the published
     * certificates and the settings reported changed.
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
     * A changed single sign-on endpoint is written, voids the flows in flight
     * and raises the trust version once.
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
     * An endpoint change reports the update then the refresh, with the
     * refresh's client and acting identity.
     *
     * @return void
     */
    public function testAnEndpointChangeReportsTheUpdateAndTheRefreshForTheClient(): void
    {
        $this->app?->instance('request', Request::create('/', 'POST', server: ['REMOTE_ADDR' => '198.51.100.9', 'HTTP_USER_AGENT' => 'Served/1.0']));
        $this->startRecordingEvents();

        $actor = new Caller(new IdentityReference('App\Models\Admin', '9'));

        $this->applier()->apply($this->claim(), self::metadata([0], ['sso_url' => self::MOVED_URL]), $this->clock->now(), new ClientContext('203.0.113.7', 'Example/1.0'), $actor);

        $this->assertEventSequence([ConnectionUpdated::class, MetadataRefreshed::class]);

        $updated = $this->recordedEvents()[0];

        self::assertInstanceOf(ConnectionUpdated::class, $updated);
        self::assertSame(['sso_url'], $updated->changedSettings);

        foreach ($this->recordedEvents() as $event) {
            self::assertSame(
                ['203.0.113.7', 'Example/1.0', 'App\Models\Admin', '9'],
                [$event->context()->ip, $event->context()->userAgent, $event->context()->actingIdentityMorphClass, $event->context()->actingIdentityId],
            );
        }
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
     * Rows of `[valid until, next refresh]`: the next refresh is never after
     * the expiry.
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
     * A refresh records the fetch, expiry and new version, resets failures,
     * releases the claim and schedules the next.
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
            [5, '2026-11-01T09:30:00+00:00', $validUntil, $next, 0, null, null],
            [
                $row->metadata_version,
                $row->metadata_fetched_at?->toIso8601String(),
                $row->metadata_valid_until?->toIso8601String(),
                $row->metadata_refresh_at?->toIso8601String(),
                $row->metadata_refresh_failures,
                $row->metadata_claimed_until,
                $row->metadata_claim_token,
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
     * Rows of `[changes, published, reason]`: metadata a refresh may not apply.
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
     * Metadata that may not be applied records a failure, backs off and
     * releases the claim, writing nothing it holds.
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
        self::assertSame([self::sortedByKey($before), 0, 0, 1, '2026-11-01T09:35:00+00:00', null, null], [
            self::sortedByKey($row->settings),
            $row->metadata_version,
            $row->trust_version,
            $row->metadata_refresh_failures,
            $row->metadata_refresh_at?->toIso8601String(),
            $row->metadata_claimed_until,
            $row->metadata_claim_token,
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
     * The fetch recorded is the moment the document was validated, carried into
     * the commit, never the clock read at commit.
     *
     * @return void
     */
    public function testTheFetchRecordedIsWhenTheDocumentWasValidated(): void
    {
        $validated = CarbonImmutable::parse('2026-11-01T09:20:00Z');

        self::assertTrue($this->applier()->apply($this->claim(), self::metadata([0]), $validated, Clients::browser())->isRefreshed());
        self::assertSame(['2026-11-01T09:20:00+00:00', '2026-12-01T09:20:00+00:00'], [
            $this->row()->metadata_fetched_at?->toIso8601String(),
            app(MetadataExpiry::class)->expiresAt($this->row())?->toIso8601String(),
        ]);
    }

    /**
     * Rows of `[validated, stale limit, outcome]`.
     *
     * @return iterable<string, array{0: string, 1: int, 2: \SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome}>
     */
    public static function provideStaleCommits(): iterable
    {
        yield from [
            'validated a limit and a second ago' => ['2026-10-02T09:29:59Z', 2592000, RefreshOutcome::FAILED],
            'validated exactly a limit ago'      => ['2026-10-02T09:30:00Z', 2592000, RefreshOutcome::FAILED],
            'validated a second within a limit'  => ['2026-10-02T09:30:01Z', 2592000, RefreshOutcome::REFRESHED],
            'validated long ago with no limit'   => ['2025-11-01T09:30:00Z', 0, RefreshOutcome::REFRESHED],
        ];
    }

    /**
     * At commit, metadata validated the stale limit or longer ago is
     * `metadata_expired`, even with no `validUntil`.
     *
     * @param  string  $validated
     * @param  int  $limit
     * @param  \SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome  $outcome
     * @return void
     */
    #[DataProvider('provideStaleCommits')]
    public function testTheStaleLimitCountsFromTheValidationAtCommit(string $validated, int $limit, RefreshOutcome $outcome): void
    {
        config()->set('sso.metadata.stale_limit_seconds', $limit);

        $result = $this->applier()->apply($this->claim(), self::metadata([0]), CarbonImmutable::parse($validated), Clients::browser());

        self::assertSame([$outcome, $outcome === RefreshOutcome::FAILED ? FailureReason::METADATA_EXPIRED : null], [$result->outcome, $result->reason]);
        self::assertSame($outcome === RefreshOutcome::FAILED ? 0 : 1, $this->row()->metadata_version);
    }

    /**
     * The earlier of the `validUntil` and the stale limit decides expiry at
     * commit.
     *
     * @return void
     */
    public function testTheEarlierOfTheValidUntilAndTheStaleLimitDecidesAtCommit(): void
    {
        $farOff = ['valid_until' => CarbonImmutable::parse('2027-01-01T00:00:00Z')];

        self::assertSame(
            RefreshOutcome::FAILED,
            $this->applier()->apply($this->claim(), self::metadata([0], $farOff), CarbonImmutable::parse('2026-10-02T09:30:00Z'), Clients::browser())->outcome,
        );
        self::assertSame(
            RefreshOutcome::REFRESHED,
            $this->applier()->apply(
                $this->claim(),
                self::metadata([0], ['valid_until' => CarbonImmutable::parse('2026-11-01T09:30:01Z')]),
                $this->clock->now(),
                Clients::browser(),
            )->outcome,
        );
    }

    /**
     * Rows of `[change]`: a change made while the refresh fetched.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideConflicts(): iterable
    {
        yield from [
            'another refresh wrote'         => ['metadata_version'],
            'the trust changed'             => ['trust_version'],
            'an anchor added'               => ['anchor_added'],
            'an anchor removed'             => ['anchor_removed'],
            'a certificate added'           => ['certificate_added'],
            'a certificate removed'         => ['certificate_removed'],
            'the claim taken over'          => ['claim_taken_over'],
            'the claim released by another' => ['claim_released'],
        ];
    }

    /**
     * A trust or version change, or a lost claim, while the refresh fetched is
     * a conflict that writes nothing.
     *
     * @param  string  $change
     * @return void
     */
    #[DataProvider('provideConflicts')]
    public function testAChangeMadeWhileFetchingIsAConflictThatWritesNothing(string $change): void
    {
        $this->connection->forceFill(['metadata_refresh_failures' => 2, 'metadata_refresh_at' => $this->clock->now()->addMinutes(10)])->save();

        if ($change === 'anchor_removed') {
            $this->trust(Certificates::distinct(8), KeyUse::METADATA_SIGNING);
        }

        $claim = $this->claim();

        $this->change($change);

        $before   = $this->row()->getAttributes();
        $trusted  = $this->trusted();
        $attempts = [
            fn (): RefreshResult => $this->applier()->apply($claim, self::metadata([1], ['sso_url' => self::MOVED_URL]), $this->clock->now(), Clients::browser()),
            fn (): RefreshResult => $this->applier()->fail($claim, FailureReason::FETCH_FAILED, Clients::browser()),
        ];

        foreach ($attempts as $attempt) {

            $this->startRecordingEvents();

            $result = $attempt();

            self::assertSame([RefreshOutcome::CONFLICT, FailureReason::METADATA_CONFLICT, []], [$result->outcome, $result->reason, $result->changedSettings]);
            self::assertSame($before, $this->row()->getAttributes());
            self::assertSame($trusted, $this->trusted());

            $this->assertEventSequence([MetadataRefreshFailed::class]);

            $failed = $this->recordedEvents()[0];

            self::assertInstanceOf(MetadataRefreshFailed::class, $failed);
            self::assertSame([FailureReason::METADATA_CONFLICT, 2, '2026-11-01T09:40:00+00:00'], [$failed->reason, $failed->failures, $failed->nextAttemptAt?->toIso8601String()]);
        }
    }

    /**
     * A certificate an administrator added while the refresh fetched survives
     * the refresh.
     *
     * @return void
     */
    public function testARefreshNeverRemovesACertificateAddedWhileItFetched(): void
    {
        $claim = $this->claim();

        $this->trust(Certificates::distinct(9));

        $result = $this->applier()->apply($claim, self::metadata([0, 1]), $this->clock->now(), Clients::browser());

        self::assertSame(RefreshOutcome::CONFLICT, $result->outcome);
        self::assertSame(self::sortedFingerprints([0, 9]), $this->trusted());
        self::assertSame([0, 0], [$this->row()->metadata_version, $this->row()->trust_version]);
    }

    /**
     * A connection deleted while the refresh fetched is a conflict reported by
     * no event, since nothing is left to report it of.
     *
     * @return void
     */
    public function testAConnectionDeletedWhileFetchingIsAConflict(): void
    {
        $claim = $this->claim();

        ConnectionKey::query()->delete();
        Connection::query()->delete();

        self::assertSame(RefreshOutcome::CONFLICT, $this->applier()->apply($claim, self::metadata([0]), $this->clock->now(), Clients::browser())->outcome);
        self::assertSame(RefreshOutcome::CONFLICT, $this->applier()->fail($claim, FailureReason::FETCH_FAILED, Clients::browser())->outcome);

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
        $waits = [];

        foreach (range(1, 9) as $failure) {

            $result  = $this->applier()->fail($this->claim(), FailureReason::FETCH_FAILED, Clients::browser());
            $waits[] = [$result->failures, (int) $this->clock->now()->diffInSeconds($result->nextAttemptAt)];

            self::assertSame(
                [$failure, $result->nextAttemptAt?->toIso8601String()],
                [$this->row()->metadata_refresh_failures, $this->row()->metadata_refresh_at?->toIso8601String()],
            );
        }

        self::assertSame([[1, 300], [2, 600], [3, 1200], [4, 2400], [5, 4800], [6, 9600], [7, 19200], [8, 21600], [9, 21600]], $waits);
        self::assertTrue($this->apply(self::metadata([0]))->isRefreshed());
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
        $claim = $this->claim();

        $this->connection->forceFill(['metadata_version' => 1])->save();

        $result = $this->applier()->fail($claim, FailureReason::FETCH_FAILED, Clients::browser(), new Caller(new IdentityReference('App\Models\User', '42')));

        self::assertSame([RefreshOutcome::CONFLICT, FailureReason::METADATA_CONFLICT], [$result->outcome, $result->reason]);
        self::assertSame([0, null], [$this->row()->metadata_refresh_failures, $this->row()->metadata_refresh_at]);
    }

    /**
     * A refresh whose claim was taken over writes nothing, and the new owner's
     * write goes through.
     *
     * @return void
     */
    public function testARefreshWhoseClaimWasTakenOverWritesNothing(): void
    {
        $stale = $this->claim();
        $owner = $this->claim();

        self::assertSame(RefreshOutcome::CONFLICT, $this->applier()->fail($stale, FailureReason::FETCH_FAILED, Clients::browser())->outcome);
        self::assertSame(RefreshOutcome::CONFLICT, $this->applier()->apply($stale, self::metadata([1]), $this->clock->now(), Clients::browser())->outcome);
        self::assertSame([$owner->token, 0, 0], [$this->row()->metadata_claim_token, $this->row()->metadata_version, $this->row()->metadata_refresh_failures]);
        self::assertTrue($this->applier()->apply($owner, self::metadata([1]), $this->clock->now(), Clients::browser())->isRefreshed());
        self::assertSame([null, 1], [$this->row()->metadata_claim_token, $this->row()->metadata_version]);
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

        self::assertSame(self::sortedByKey([
            'outcome'          => 'failed',
            'connection_id'    => 'c1',
            'reason'           => 'fetch_failed',
            'changed_settings' => [],
            'metadata_version' => null,
            'trust_changed'    => false,
            'failures'         => 2,
            'next_attempt_at'  => '2026-11-01T10:00:00+00:00',
            'retry_after'      => null,
        ]), self::sortedByKey($failed->jsonSerialize()));
        self::assertSame(self::sortedByKey([
            'outcome'          => 'refreshed',
            'connection_id'    => 'c1',
            'reason'           => null,
            'changed_settings' => ['sso_url'],
            'metadata_version' => 3,
            'trust_changed'    => true,
            'failures'         => null,
            'next_attempt_at'  => null,
            'retry_after'      => null,
        ]), self::sortedByKey(RefreshResult::refreshed('c1', ['sso_url'], 3, true)->jsonSerialize()));

        $limited = RefreshResult::rateLimited('c1', 42);

        self::assertSame(
            ['rate_limited', 'c1', 'rate_limited', 42, 42],
            [$limited->outcome->value, $limited->connectionId, $limited->reason?->value, $limited->retryAfter, $limited->jsonSerialize()['retry_after']],
        );
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
     * The locked snapshot lists each use's fingerprints in order, with an empty
     * list for an unused one.
     *
     * @return void
     */
    public function testTheLockedSnapshotHoldsEachUseInOrder(): void
    {
        $this->trust(Certificates::distinct(5));
        $this->trust(Certificates::distinct(6));

        $fingerprints = $this->trusted();

        self::assertCount(3, $fingerprints);
        self::assertSame(['idp_signing' => $fingerprints, 'metadata_signing' => []], MetadataApplier::trustedOf($this->row()));

        $this->trust(Certificates::distinct(8), KeyUse::METADATA_SIGNING);

        self::assertCount(1, MetadataApplier::trustedOf($this->row())['metadata_signing']);
    }

    /**
     * Claim the connection as it is now and apply the metadata, validated now.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata  $metadata
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     */
    private function apply(IdpMetadata $metadata): RefreshResult
    {
        return $this->applier()->apply($this->claim(), $metadata, $this->clock->now(), Clients::browser());
    }

    /**
     * Claim the connection as the refresher does, snapshotting it, its
     * certificates and its anchors.
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
     * Make the change another server or an administrator would make while the
     * refresh fetched.
     *
     * @param  string  $change
     * @return void
     */
    private function change(string $change): void
    {
        $query = Connection::query()->whereKey($this->connection->id);

        match ($change) {
            'anchor_added'        => $this->trust(Certificates::distinct(8), KeyUse::METADATA_SIGNING),
            'anchor_removed'      => ConnectionKey::query()->where('use', KeyUse::METADATA_SIGNING->value)->delete(),
            'certificate_added'   => $this->trust(Certificates::distinct(9)),
            'certificate_removed' => ConnectionKey::query()->where('use', KeyUse::IDP_SIGNING->value)->delete(),
            'claim_taken_over'    => $query->update(['metadata_claim_token' => str_repeat('b', 32)]),
            'claim_released'      => $query->update(['metadata_claim_token' => null]),
            default               => $query->update([$change => 7]),
        };
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
     * The sorted fingerprints of the signing certificates the connection
     * trusts.
     *
     * @return list<string>
     */
    private function trusted(): array
    {
        $fingerprints = ConnectionKey::query()->where('use', KeyUse::IDP_SIGNING->value)->pluck('fingerprint')->all();

        self::assertContainsOnlyString($fingerprints);

        sort($fingerprints);

        return $fingerprints;
    }

    /**
     * The provider's metadata publishing the certificates at the indices given,
     * with the changes.
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
