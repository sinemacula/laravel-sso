<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\MetadataRefreshed;
use SineMacula\Laravel\Sso\Events\MetadataRefreshFailed;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\RefreshClaim;
use SineMacula\Laravel\Sso\Metadata\RefreshResult;
use SineMacula\Laravel\Sso\Metadata\RefreshWriter;
use SineMacula\Laravel\Sso\Models\Connection;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for what every refresh source's write shares (SSO-2.8,
 * SSO-2.13): the locked compare and set on the claim's token, the metadata and
 * trust versions and the source's snapshot, each mismatching alone; the
 * failure's backoff and released claim; the success's bookkeeping and next
 * refresh; and what each reports.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshWriter::class)]
final class RefreshWriterTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /** @var string The token the connection's claim was written with. */
    private const string TOKEN = 'the-claims-token';

    /** @var array<string, mixed> The snapshot of the connection's trust. */
    private const array TRUSTED = ['first' => 1, 'second' => 2];

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T09:30:00+00:00';

    /** @var \Tests\Fixtures\FixedClock The clock the writer reads. */
    private FixedClock $clock;

    /**
     * Bind a fixed clock, create the tables and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock(self::NOW);

        $this->app?->instance(Clock::class, $this->clock);

        $this->createConnectionTables();
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
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * With its claim still held and nothing changed, the work runs on the
     * connection read again, inside one transaction on the storage connection,
     * and answers for the refresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnchangedConnectionIsWorkedOnInATransaction(): void
    {
        $claim    = $this->claim();
        $expected = RefreshResult::skipped($claim->connection->id);
        $seen     = [];

        $result = $this->writer()->locked($claim, static fn (): array => self::TRUSTED, static function (Connection $locked) use (&$seen, $expected): RefreshResult {
            $seen = [$locked->id, $locked->metadata_claim_token, DB::connection(StorageConnection::name())->transactionLevel()];

            return $expected;
        }, null);

        self::assertSame($expected, $result);
        self::assertSame([$claim->connection->id, self::TOKEN, 1], $seen);
        $this->assertNoEvents();
    }

    /**
     * Rows of `[columns]`: what changed while the refresh fetched, each alone.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideChanges(): iterable
    {
        yield from [
            'the claim taken over'     => [['metadata_claim_token' => 'another-token']],
            'the claim released'       => [['metadata_claim_token' => null]],
            'another refresh wrote'    => [['metadata_version' => 3]],
            'the trust version raised' => [['trust_version' => 3]],
        ];
    }

    /**
     * Any of them is a conflict: the work never runs, nothing is written, and
     * the failure reports the connection as the winner left it.
     *
     * @param  array<string, mixed>  $columns
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChanges')]
    public function testAChangeIsAConflictThatWritesNothing(array $columns): void
    {
        $claim = $this->claim();
        $next  = $this->clock->now()->addHour();

        Connection::query()->whereKey($claim->connection->id)->update([...$columns, 'metadata_refresh_failures' => 4, 'metadata_refresh_at' => $next]);

        $before = $this->row($claim)->getAttributes();
        $result = $this->writer()->locked($claim, static fn (): array => self::TRUSTED, self::neverRuns(...), new ActingIdentity('App\Models\User', '42'));

        $this->assertConflict($result, $claim);
        self::assertSame($before, $this->row($claim)->getAttributes());
        $this->assertEventSequence([MetadataRefreshFailed::class]);

        $failed = $this->recordedEvents()[0];

        self::assertInstanceOf(MetadataRefreshFailed::class, $failed);
        self::assertSame([FailureReason::METADATA_CONFLICT, 4, $next->toIso8601String()], [$failed->reason, $failed->failures, $failed->nextAttemptAt?->toIso8601String()]);
        self::assertSame('42', $failed->context()->actingIdentityId);
    }

    /**
     * Rows of `[snapshot]`: the source's snapshot, read again under the lock,
     * that is not exactly the claim's.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideSnapshots(): iterable
    {
        yield from [
            'a value changed' => [['first' => 1, 'second' => 3]],
            'a value removed' => [['first' => 1]],
            'another order'   => [['second' => 2, 'first' => 1]],
            'another type'    => [['first' => '1', 'second' => 2]],
        ];
    }

    /**
     * A snapshot that is not exactly the claim's is a conflict too, read from
     * the locked connection.
     *
     * @param  array<string, mixed>  $snapshot
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSnapshots')]
    public function testAChangedSnapshotIsAConflict(array $snapshot): void
    {
        $claim = $this->claim();
        $read  = null;

        $result = $this->writer()->locked($claim, static function (Connection $locked) use (&$read, $snapshot): array {
            $read = $locked->id;

            return $snapshot;
        }, self::neverRuns(...), null);

        $this->assertConflict($result, $claim);
        self::assertSame($claim->connection->id, $read);
        self::assertSame(self::TOKEN, $this->row($claim)->metadata_claim_token);
    }

    /**
     * A connection deleted while the refresh fetched is a conflict with nothing
     * to report: neither the snapshot nor the work is read.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testADeletedConnectionIsAConflictWithNoEvent(): void
    {
        $claim = $this->claim();

        Connection::query()->whereKey($claim->connection->id)->delete();

        $result = $this->writer()->locked($claim, static fn (): array => throw new \LogicException('The snapshot was read.'), self::neverRuns(...), null);

        $this->assertConflict($result, $claim);
        $this->assertNoEvents();
    }

    /**
     * Rows of `[failures before, failures after, backoff]`: how a failure backs
     * off for the failures in a row.
     *
     * @return iterable<string, array{0: int, 1: int, 2: int}>
     */
    public static function provideFailures(): iterable
    {
        yield from [
            'the first'  => [0, 1, 300],
            'the second' => [1, 2, 600],
            'the ninth'  => [8, 9, 21600],
        ];
    }

    /**
     * A failure raises the failures in a row, backs off for that many, releases
     * the claim and its token, keeps everything else, and reports them.
     *
     * @param  int  $before
     * @param  int  $after
     * @param  int  $backoff
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    #[DataProvider('provideFailures')]
    public function testAFailureBacksOffAndReleasesTheClaim(int $before, int $after, int $backoff): void
    {
        $claim = $this->claim(['metadata_refresh_failures' => $before, 'metadata_claimed_until' => $this->clock->now()->addMinute()]);
        $next  = $this->clock->now()->addSeconds($backoff);

        $result = $this->writer()->failed($this->row($claim), FailureReason::FETCH_FAILED, null);
        $row    = $this->row($claim);

        self::assertSame(
            [RefreshOutcome::FAILED, $claim->connection->id, FailureReason::FETCH_FAILED, $after, $next->toIso8601String()],
            [$result->outcome, $result->connectionId, $result->reason, $result->failures, $result->nextAttemptAt?->toIso8601String()],
        );
        self::assertSame(
            [$after, $next->toIso8601String(), null, null, 2, 2, null],
            [
                $row->metadata_refresh_failures,
                $row->metadata_refresh_at?->toIso8601String(),
                $row->metadata_claimed_until,
                $row->metadata_claim_token,
                $row->metadata_version,
                $row->trust_version,
                $row->metadata_fetched_at,
            ],
        );

        $this->assertEventSequence([MetadataRefreshFailed::class]);

        $failed = $this->recordedEvents()[0];

        self::assertInstanceOf(MetadataRefreshFailed::class, $failed);
        self::assertSame([FailureReason::FETCH_FAILED, $after, $next->toIso8601String()], [$failed->reason, $failed->failures, $failed->nextAttemptAt?->toIso8601String()]);
    }

    /**
     * A success writes the source's attributes with the refresh's bookkeeping,
     * in one save: the metadata version raised, the validated moment and the
     * `validUntil` as given, the failures reset and the claim released.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function testASuccessWritesItsBookkeeping(): void
    {
        $claim      = $this->claim(['metadata_refresh_failures' => 3, 'metadata_claimed_until' => $this->clock->now()->addMinute()]);
        $validated  = $this->clock->now()->subSeconds(7);
        $validUntil = $this->clock->now()->addDays(9);

        $this->writer()->succeeded($this->row($claim), ['display_name' => 'Renamed'], $validated, $validUntil);

        $row = $this->row($claim);

        self::assertSame(
            ['Renamed', 3, 2, $validated->toIso8601String(), $validUntil->toIso8601String(), 0, null, null],
            [
                $row->display_name,
                $row->metadata_version,
                $row->trust_version,
                $row->metadata_fetched_at?->toIso8601String(),
                $row->metadata_valid_until?->toIso8601String(),
                $row->metadata_refresh_failures,
                $row->metadata_claimed_until,
                $row->metadata_claim_token,
            ],
        );
    }

    /**
     * Rows of `[valid until, next]`: a refresh's `validUntil` around the
     * interval, in seconds from now, and when the next refresh is due; `null`
     * for none.
     *
     * @return iterable<string, array{0: ?int, 1: int}>
     */
    public static function provideNextRefreshes(): iterable
    {
        yield from [
            'no valid until'            => [null, 86400],
            'a second under the period' => [86399, 86399],
            'at the period'             => [86400, 86400],
            'a second over the period'  => [86401, 86400],
        ];
    }

    /**
     * The next refresh is due after the interval, never after the `validUntil`.
     *
     * @param  ?int  $validUntil
     * @param  int  $next
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    #[DataProvider('provideNextRefreshes')]
    public function testTheNextRefreshIsNeverAfterTheValidUntil(?int $validUntil, int $next): void
    {
        $claim = $this->claim();
        $now   = $this->clock->now();

        $this->writer()->succeeded($this->row($claim), [], $now, $validUntil === null ? null : $now->addSeconds($validUntil));

        self::assertSame($now->addSeconds($next)->toIso8601String(), $this->row($claim)->metadata_refresh_at?->toIso8601String());
    }

    /**
     * The next refresh counts from the commit, not from the moment validated.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function testTheNextRefreshCountsFromTheCommit(): void
    {
        $claim = $this->claim();

        $this->writer()->succeeded($this->row($claim), [], CarbonImmutable::parse('2026-10-31T09:30:00Z'));

        self::assertSame('2026-11-02T09:30:00+00:00', $this->row($claim)->metadata_refresh_at?->toIso8601String());
    }

    /**
     * A refresh reports the settings changed, the connection's metadata version
     * and whether its trust changed, and answers them.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function testARefreshReportsAndAnswersWhatChanged(): void
    {
        $claim  = $this->claim();
        $result = $this->writer()->refreshed($this->row($claim), ['issuer', 'jwks'], true, new ActingIdentity('App\Models\User', '42'));

        self::assertSame(
            [RefreshOutcome::REFRESHED, $claim->connection->id, ['issuer', 'jwks'], 2, true],
            [$result->outcome, $result->connectionId, $result->changedSettings, $result->metadataVersion, $result->trustChanged],
        );

        $this->assertEventSequence([MetadataRefreshed::class]);

        $refreshed = $this->recordedEvents()[0];

        self::assertInstanceOf(MetadataRefreshed::class, $refreshed);
        self::assertSame([['issuer', 'jwks'], 2, true], [$refreshed->changedSettings, $refreshed->metadataVersion, $refreshed->trustChanged]);
        self::assertSame('42', $refreshed->context()->actingIdentityId);
    }

    /**
     * Assert the result is a conflict over the claim's connection.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshResult  $result
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @return void
     */
    private function assertConflict(RefreshResult $result, RefreshClaim $claim): void
    {
        self::assertSame([RefreshOutcome::CONFLICT, FailureReason::METADATA_CONFLICT, $claim->connection->id], [$result->outcome, $result->reason, $result->connectionId]);
    }

    /**
     * A connection with a claim written and the attributes given, and the claim
     * as a refresh read it: both versions at 2, the snapshot `TRUSTED`.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshClaim
     */
    private function claim(array $attributes = []): RefreshClaim
    {
        $connection = $this->makeConnection(['metadata_version' => 2, 'trust_version' => 2, 'metadata_claim_token' => self::TOKEN, ...$attributes]);

        return new RefreshClaim($connection, self::TOKEN, self::TRUSTED);
    }

    /**
     * The claimed connection as stored now, read on the write connection.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function row(RefreshClaim $claim): Connection
    {
        return Connection::query()->useWritePdo()->whereKey($claim->connection->id)->firstOrFail();
    }

    /**
     * The writer, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshWriter
     */
    private function writer(): RefreshWriter
    {
        return app(RefreshWriter::class);
    }

    /**
     * Work a conflict must never run.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \LogicException
     */
    private static function neverRuns(): RefreshResult
    {
        throw new \LogicException('The work ran.');
    }
}
