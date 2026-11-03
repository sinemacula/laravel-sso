<?php

declare(strict_types = 1);

namespace Tests\Feature\Pruning;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Models\RateLimit;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneKind;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneStatus;
use SineMacula\Laravel\Sso\Pruning\PruneCandidate;
use SineMacula\Laravel\Sso\Pruning\PruneFailedException;
use SineMacula\Laravel\Sso\Pruning\Pruner;
use SineMacula\Laravel\Sso\Pruning\PruneReport;
use SineMacula\Laravel\Sso\Pruning\PruneSettings;
use SineMacula\Laravel\Sso\Pruning\PruneSweep;
use SineMacula\Laravel\Sso\Pruning\PruneTarget;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\FailsDatabaseStatements;
use Tests\Concerns\MakesPrunableRows;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Pruning\TickingClock;
use Tests\TestCase;

/**
 * Feature tests for the clean-up (SSO-11.11): each kind's eligibility at both
 * sides of its boundary, what each kind's state does and does not change, the
 * retention, keyset traversal across batches and ties, the eligibility repeated
 * in the delete, a batch another server emptied, one instant per run, the work
 * cap and the drain, the links version, partial failure and starting again, the
 * refusal of an open transaction on either connection, the write connection, a
 * connection of the storage's own and of the counters', renamed and
 * schema-qualified tables, the one log line, and no event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Pruner::class)]
#[CoversClass(PruneTarget::class)]
#[CoversClass(PruneCandidate::class)]
#[CoversClass(PruneSweep::class)]
#[CoversClass(PruneReport::class)]
#[CoversClass(PruneFailedException::class)]
#[CoversClass(ReservationWithdrawal::class)]
#[CoversClass(StorageConnection::class)]
final class PrunerTest extends TestCase
{
    use CapturesLogs, FailsDatabaseStatements, MakesPrunableRows, RecordsEventSequences, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The instant the clock holds. */
    private const string NOW = '2026-11-01T12:00:00Z';

    /** @var int The default retention, in seconds. */
    private const int RETENTION = 86400;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The shipped migration of the counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the rows belong to. */
    private Connection $connection;

    /**
     * Bind a fixed clock, create the tables and a connection, record events and
     * capture logs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock(self::NOW));

        $this->createPruningTables();

        $this->connection = $this->makeConnection(['protocol' => 'saml2']);

        $this->captureLogs();
        $this->startRecordingEvents();
    }

    /**
     * Drop the tables, restoring any name a test changed first.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropPruningTables();

        parent::tearDown();
    }

    /**
     * Rows of `[kind, the seconds before now its time must be to be eligible]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind, 1: int}>
     */
    public static function provideEligibility(): iterable
    {
        yield 'requests, past the retention' => [PruneKind::AUTHORIZATION_REQUESTS, self::RETENTION];
        yield 'handoff codes, past the retention' => [PruneKind::HANDOFF_CODES, self::RETENTION];
        yield 'single-use keys, on expiry' => [PruneKind::SINGLE_USE_KEYS, 0];
        yield 'reservations, on expiry' => [PruneKind::RESERVATIONS, 0];
        yield 'pending claims, on expiry' => [PruneKind::PENDING_CLAIMS, 0];
        yield 'counters, as the window ends' => [PruneKind::RATE_LIMITS, 0];
    }

    /**
     * A row is deleted from the very second its kind's boundary names, and a
     * row a second short of it stands, with every other kind's count at
     * nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @param  int  $before
     * @return void
     */
    #[DataProvider('provideEligibility')]
    public function testEachKindGoesFromItsBoundaryAndNotBefore(PruneKind $kind, int $before): void
    {
        $now = CarbonImmutable::parse(self::NOW);

        $this->prunableRow($kind, $this->connection, $now->subSeconds($before + 3600));
        $this->prunableRow($kind, $this->connection, $now->subSeconds($before));

        $kept = $this->prunableRow($kind, $this->connection, $now->subSeconds($before - 1));

        $report = $this->pruner()->run();

        self::assertSame([$kept], $this->prunableRowsLeft($kind));
        self::assertSame(2, $report->deleted($kind));
        self::assertSame(2, $report->total());
        self::assertSame(PruneStatus::COMPLETE, $report->status);
        self::assertTrue($report->isComplete());
    }

    /**
     * Rows of `[column]`: what has happened to a request.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRequestStates(): iterable
    {
        yield 'consumed' => ['consumed_at'];
        yield 'verified' => ['verified_at'];
        yield 'voided' => ['voided_at'];
        yield 'completed' => ['completed_at'];
    }

    /**
     * A request is judged by its expiry alone: a finished one inside the
     * retention stands, and an unfinished one past it goes.
     *
     * @param  string  $column
     * @return void
     */
    #[DataProvider('provideRequestStates')]
    public function testARequestIsJudgedByItsExpiryWhateverHappenedToIt(string $column): void
    {
        $now  = CarbonImmutable::parse(self::NOW);
        $kept = $this->makeAuthorizationRequest($this->connection, ['expires_at' => $now->subSeconds(self::RETENTION - 1), $column => $now->subDay()]);
        $gone = $this->makeAuthorizationRequest($this->connection, ['expires_at' => $now->subSeconds(self::RETENTION), $column => $now->subDay()]);

        $this->makeAuthorizationRequest($this->connection, ['expires_at' => $now->subSeconds(self::RETENTION)]);

        self::assertSame(2, $this->pruner()->run()->deleted(PruneKind::AUTHORIZATION_REQUESTS));
        self::assertTrue(AuthorizationRequest::query()->whereKey($kept->id)->exists());
        self::assertFalse(AuthorizationRequest::query()->whereKey($gone->id)->exists());
    }

    /**
     * Rows of `[column]`: what has happened to a code.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideCodeStates(): iterable
    {
        yield 'redeemed' => ['redeemed_at'];
        yield 'voided' => ['voided_at'];
    }

    /**
     * A code too is judged by its expiry alone: redeeming or voiding it does
     * not bring its deletion forward.
     *
     * @param  string  $column
     * @return void
     */
    #[DataProvider('provideCodeStates')]
    public function testACodeIsJudgedByItsExpiryWhateverHappenedToIt(string $column): void
    {
        $now  = CarbonImmutable::parse(self::NOW);
        $kept = $this->makeHandoffCode($this->connection, ['expires_at' => $now->subSeconds(self::RETENTION - 1), $column => $now->subDay()]);

        $this->makeHandoffCode($this->connection, ['expires_at' => $now->subSeconds(self::RETENTION), $column => $now->subDay()]);

        self::assertSame(1, $this->pruner()->run()->deleted(PruneKind::HANDOFF_CODES));
        self::assertSame([$kept->id], array_values(HandoffCode::query()->pluck('id')->all()));
    }

    /**
     * Rows of `[state]`: a link no longer reserved.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Links\Enums\LinkState}>
     */
    public static function provideLinkStatesKept(): iterable
    {
        yield 'active' => [LinkState::ACTIVE];
        yield 'suspended' => [LinkState::SUSPENDED];
    }

    /**
     * Only a reservation goes: a row of another state stands, whatever its
     * expiry says, and the links version stays.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $state
     * @return void
     */
    #[DataProvider('provideLinkStatesKept')]
    public function testALinkNoLongerReservedStands(LinkState $state): void
    {
        $this->makeLink($this->connection, 'subject', ['state' => $state, 'reservation_expires_at' => CarbonImmutable::parse(self::NOW)->subDay()]);

        self::assertSame(0, $this->pruner()->run()->deleted(PruneKind::RESERVATIONS));
        self::assertSame(1, Link::query()->count());
        self::assertSame(0, $this->linksVersion($this->connection));
    }

    /**
     * Rows of `[state]`: a claim no longer pending.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Domains\Enums\DomainState}>
     */
    public static function provideClaimStatesKept(): iterable
    {
        yield 'verified' => [DomainState::VERIFIED];
        yield 'lapsed' => [DomainState::LAPSED];
    }

    /**
     * Only a pending claim goes: a verified or lapsed one stands, whatever its
     * old expiry says.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\DomainState  $state
     * @return void
     */
    #[DataProvider('provideClaimStatesKept')]
    public function testAClaimNoLongerPendingStands(DomainState $state): void
    {
        $this->makeDomain($this->connection, 'kept.example.com', ['state' => $state, 'pending_expires_at' => CarbonImmutable::parse(self::NOW)->subDay()]);

        self::assertSame(0, $this->pruner()->run()->deleted(PruneKind::PENDING_CLAIMS));
        self::assertSame(1, Domain::query()->count());
    }

    /**
     * The retention moves the boundary of requests and codes, and only theirs;
     * none at all takes them at their expiry.
     *
     * @return void
     */
    public function testTheRetentionMovesTheBoundaryOfRequestsAndCodesAlone(): void
    {
        $now = CarbonImmutable::parse(self::NOW);

        config()->set('sso.pruning.retention_seconds', 0);

        $this->prunableRow(PruneKind::AUTHORIZATION_REQUESTS, $this->connection, $now);
        $this->prunableRow(PruneKind::HANDOFF_CODES, $this->connection, $now);

        $request = $this->prunableRow(PruneKind::AUTHORIZATION_REQUESTS, $this->connection, $now->addSecond());

        self::assertSame(2, $this->pruner()->run()->total());
        self::assertSame([$request], $this->prunableRowsLeft(PruneKind::AUTHORIZATION_REQUESTS));

        config()->set('sso.pruning.retention_seconds', 3600);

        $kept = $this->prunableRow(PruneKind::HANDOFF_CODES, $this->connection, $now->subSeconds(3599));
        $key  = $this->prunableRow(PruneKind::SINGLE_USE_KEYS, $this->connection, $now);

        $this->prunableRow(PruneKind::HANDOFF_CODES, $this->connection, $now->subSeconds(3600));

        $report = $this->pruner()->run();

        self::assertSame(1, $report->deleted(PruneKind::HANDOFF_CODES));
        self::assertSame(1, $report->deleted(PruneKind::SINGLE_USE_KEYS));
        self::assertSame([$kept], $this->prunableRowsLeft(PruneKind::HANDOFF_CODES));
        self::assertNotContains($key, $this->prunableRowsLeft(PruneKind::SINGLE_USE_KEYS));
    }

    /**
     * Every eligible row of every kind goes across batches, those sharing a
     * second by their key, and the count is of what went.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @param  int  $before
     * @return void
     */
    #[DataProvider('provideEligibility')]
    public function testBatchesTraverseEveryRowAcrossTies(PruneKind $kind, int $before): void
    {
        $now = CarbonImmutable::parse(self::NOW)->subSeconds($before);

        config()->set('sso.pruning.batch_size', 2);

        for ($row = 0; $row < 5; $row++) {
            $this->prunableRow($kind, $this->connection, $now);
        }

        for ($row = 0; $row < 2; $row++) {
            $this->prunableRow($kind, $this->connection, $now->subSecond());
        }

        $report = $this->pruner()->run();

        self::assertSame(7, $report->deleted($kind));
        self::assertSame([], $this->prunableRowsLeft($kind));
    }

    /**
     * Each page continues after the last row of the one before it, in the order
     * of the time and then the key, and names exactly as many rows as asked.
     *
     * @return void
     */
    public function testAPageContinuesAfterTheLastRowInTimeThenKeyOrder(): void
    {
        $now  = CarbonImmutable::parse(self::NOW);
        $late = $this->counter('c', $now->subSecond());
        $a    = $this->counter('a', $now->subSeconds(5));
        $b    = $this->counter('b', $now->subSeconds(5));

        $target = $this->target(PruneKind::RATE_LIMITS);

        $first = $target->candidates(null, 2);

        self::assertSame([$a, $b], array_map(static fn (PruneCandidate $candidate): int|string => $candidate->key, $first));
        self::assertSame(['2026-11-01 11:59:55', '2026-11-01 11:59:55'], array_map(static fn (PruneCandidate $candidate): string => $candidate->time, $first));

        self::assertSame([$b], array_map(static fn (PruneCandidate $candidate): int|string => $candidate->key, $target->candidates($first[0], 1)));
        self::assertSame([$late], array_map(static fn (PruneCandidate $candidate): int|string => $candidate->key, $target->candidates($first[1], 2)));
        self::assertSame([], $target->candidates(new PruneCandidate($late, '2026-11-01 11:59:59'), 2));
    }

    /**
     * A row that became ineligible after it was selected stands, and the count
     * says what went rather than what was selected.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @param  int  $before
     * @return void
     */
    #[DataProvider('provideEligibility')]
    public function testTheDeleteRepeatsTheEligibility(PruneKind $kind, int $before): void
    {
        $now  = CarbonImmutable::parse(self::NOW);
        $at   = $now->subSeconds($before);
        $kept = $this->prunableRow($kind, $this->connection, $at);

        $this->prunableRow($kind, $this->connection, $at);

        $this->beforeTheFirstDelete(function () use ($kind, $kept, $now): void {
            $this->renew($kind, $kept, $now);
        });

        $report = $this->pruner()->run();

        self::assertSame(1, $report->deleted($kind));
        self::assertSame([$kept], $this->prunableRowsLeft($kind));
    }

    /**
     * A reservation activated after it was selected stands and is no longer a
     * reservation, and the links version rises only for what went.
     *
     * @return void
     */
    public function testAReservationActivatedAfterItWasSelectedStands(): void
    {
        $at   = CarbonImmutable::parse(self::NOW)->subMinute();
        $kept = $this->reservationRow($this->connection, 901, $at);

        $this->beforeTheFirstDelete(static function () use ($kept): void {
            Link::query()->whereKey($kept->id)->update(['state' => LinkState::ACTIVE->value, 'reservation_expires_at' => null]);
        });

        self::assertSame(0, $this->pruner()->run()->deleted(PruneKind::RESERVATIONS));
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        self::assertSame(0, $this->linksVersion($this->connection));
    }

    /**
     * A batch another server has already emptied does not end the scan: what
     * comes after it still goes, and only that is counted.
     *
     * @return void
     */
    public function testABatchAnotherServerEmptiedDoesNotEndTheScan(): void
    {
        $now   = CarbonImmutable::parse(self::NOW);
        $first = [$this->counter('a', $now->subMinute()), $this->counter('b', $now->subMinute())];

        $this->counter('c', $now->subSecond());

        config()->set('sso.pruning.batch_size', 2);

        $this->beforeTheFirstDelete(static function () use ($first): void {
            RateLimit::query()->whereKey($first)->delete();
        });

        $report = $this->pruner()->run();

        self::assertSame(1, $report->deleted(PruneKind::RATE_LIMITS));
        self::assertSame(0, RateLimit::query()->count());
        self::assertTrue($report->isComplete());
    }

    /**
     * A run reads the clock for its one instant: however long the run takes, a
     * row eligible only by a later reading stands. The clock's second reading
     * is for the duration alone.
     *
     * @return void
     */
    public function testARunJudgesEveryKindByOneInstant(): void
    {
        $clock = new TickingClock(self::NOW, 5);
        $now   = CarbonImmutable::parse(self::NOW);

        $this->app?->instance(Clock::class, new FixedClock(self::NOW));

        $request = $this->prunableRow(PruneKind::AUTHORIZATION_REQUESTS, $this->connection, $now->subSeconds(self::RETENTION - 1));
        $code    = $this->prunableRow(PruneKind::HANDOFF_CODES, $this->connection, $now->subSeconds(self::RETENTION - 1));
        $counter = $this->prunableRow(PruneKind::RATE_LIMITS, $this->connection, $now->addSecond());
        $claim   = $this->prunableRow(PruneKind::PENDING_CLAIMS, $this->connection, $now->addSecond());

        $this->app?->instance(Clock::class, $clock);

        $report = $this->pruner()->run();

        self::assertSame(0, $report->total());
        self::assertSame([$request], $this->prunableRowsLeft(PruneKind::AUTHORIZATION_REQUESTS));
        self::assertSame([$code], $this->prunableRowsLeft(PruneKind::HANDOFF_CODES));
        self::assertSame([$counter], $this->prunableRowsLeft(PruneKind::RATE_LIMITS));
        self::assertSame([$claim], $this->prunableRowsLeft(PruneKind::PENDING_CLAIMS));
        self::assertSame(2, $clock->reads);
        self::assertSame(5000, $report->durationMilliseconds);
        self::assertSame(self::NOW, $report->now->format('Y-m-d\TH:i:s\Z'));
    }

    /**
     * A kind stops at its work cap with more eligible, and says so; every other
     * kind still has its turn; the next run goes on; a batch is cut short to
     * land on the cap exactly.
     *
     * @return void
     */
    public function testTheWorkCapStopsAKindWithoutStarvingTheRest(): void
    {
        $now = CarbonImmutable::parse(self::NOW)->subDays(2);

        config()->set('sso.pruning.batch_size', 2);
        config()->set('sso.pruning.max_rows_per_kind', 3);

        for ($row = 0; $row < 5; $row++) {
            $this->prunableRow(PruneKind::AUTHORIZATION_REQUESTS, $this->connection, $now);
        }

        $this->prunableRow(PruneKind::RATE_LIMITS, $this->connection, $now);

        $report = $this->pruner()->run();

        self::assertSame(PruneStatus::INCOMPLETE, $report->status);
        self::assertFalse($report->isComplete());
        self::assertSame([PruneKind::AUTHORIZATION_REQUESTS], $report->incomplete);
        self::assertSame(3, $report->deleted(PruneKind::AUTHORIZATION_REQUESTS));
        self::assertSame(1, $report->deleted(PruneKind::RATE_LIMITS));
        self::assertCount(2, $this->prunableRowsLeft(PruneKind::AUTHORIZATION_REQUESTS));

        $next = $this->pruner()->run();

        self::assertSame(2, $next->deleted(PruneKind::AUTHORIZATION_REQUESTS));
        self::assertSame(PruneStatus::COMPLETE, $next->status);
        self::assertSame([], $next->incomplete);
    }

    /**
     * A cap landing exactly on the last eligible row is complete: the run looks
     * for more rather than guessing from a full batch.
     *
     * @return void
     */
    public function testACapLandingOnTheLastRowIsComplete(): void
    {
        $now = CarbonImmutable::parse(self::NOW)->subDays(2);

        config()->set('sso.pruning.batch_size', 2);
        config()->set('sso.pruning.max_rows_per_kind', 4);

        for ($row = 0; $row < 4; $row++) {
            $this->prunableRow(PruneKind::HANDOFF_CODES, $this->connection, $now);
        }

        $report = $this->pruner()->run();

        self::assertSame(4, $report->deleted(PruneKind::HANDOFF_CODES));
        self::assertSame(PruneStatus::COMPLETE, $report->status);
    }

    /**
     * A cap smaller than the batch is the most any run looks at.
     *
     * @return void
     */
    public function testACapSmallerThanTheBatchIsHeld(): void
    {
        $now = CarbonImmutable::parse(self::NOW)->subDays(2);

        config()->set('sso.pruning.batch_size', 100);
        config()->set('sso.pruning.max_rows_per_kind', 1);

        $this->prunableRow(PruneKind::RATE_LIMITS, $this->connection, $now);
        $this->prunableRow(PruneKind::RATE_LIMITS, $this->connection, $now);

        $report = $this->pruner()->run();

        self::assertSame(1, $report->deleted(PruneKind::RATE_LIMITS));
        self::assertSame(PruneStatus::INCOMPLETE, $report->status);
    }

    /**
     * A drain takes no cap: every row eligible at its one instant goes.
     *
     * @return void
     */
    public function testADrainGoesPastTheCap(): void
    {
        $now = CarbonImmutable::parse(self::NOW)->subDays(2);

        config()->set('sso.pruning.batch_size', 2);
        config()->set('sso.pruning.max_rows_per_kind', 1);

        for ($row = 0; $row < 5; $row++) {
            $this->prunableRow(PruneKind::SINGLE_USE_KEYS, $this->connection, $now);
        }

        $report = $this->pruner()->run(true);

        self::assertSame(5, $report->deleted(PruneKind::SINGLE_USE_KEYS));
        self::assertSame(PruneStatus::COMPLETE, $report->status);
    }

    /**
     * Reservations go one short transaction for each connection, ascending, and
     * raise each connection's links version once a batch for what went from it;
     * another connection's and a connection with nothing eligible stay.
     *
     * @return void
     */
    public function testReservationsRaiseEachConnectionsVersion(): void
    {
        $now     = CarbonImmutable::parse(self::NOW)->subMinute();
        $other   = $this->makeConnection(['tenant_id' => 'tenant-2', 'protocol' => 'saml2']);
        $third   = $this->makeConnection(['tenant_id' => 'tenant-3', 'protocol' => 'saml2']);
        $live    = $this->reservationRow($third, 900, $now->addHour());
        $locks   = [];
        $ordered = [$this->connection->id, $other->id];

        sort($ordered);

        $this->reservationRow($this->connection, 901, $now);
        $this->reservationRow($this->connection, 902, $now);
        $this->reservationRow($other, 903, $now);

        DB::connection(StorageConnection::name())->listen(static function ($query) use (&$locks): void {

            if (!str_contains(strtolower($query->sql), 'delete')) {
                return;
            }

            $locks[] = $query->bindings[0];
        });

        self::assertSame(3, $this->pruner()->run()->deleted(PruneKind::RESERVATIONS));
        self::assertSame(1, $this->linksVersion($this->connection));
        self::assertSame(1, $this->linksVersion($other));
        self::assertSame(0, $this->linksVersion($third));
        self::assertSame($ordered, $locks);
        self::assertSame([$live->id], array_values(Link::query()->pluck('id')->all()));
    }

    /**
     * A reservation whose connection is gone is deleted just the same, with no
     * version to raise.
     *
     * @return void
     */
    public function testAReservationOfAConnectionGoneIsDeleted(): void
    {
        $gone = $this->makeConnection(['tenant_id' => 'tenant-2', 'protocol' => 'saml2']);

        $this->reservationRow($gone, 901, CarbonImmutable::parse(self::NOW)->subMinute());

        Connection::query()->whereKey($gone->id)->delete();

        self::assertSame(1, $this->pruner()->run()->deleted(PruneKind::RESERVATIONS));
        self::assertSame(0, Link::query()->count());
    }

    /**
     * A failure stops the kind it came from, keeping the batches that committed
     * before it; every other kind still has its turn; the exception that comes
     * out names the kind and the class alone and holds the report; a run begun
     * again finishes the rest.
     *
     * @return void
     */
    public function testAFailureKeepsWhatCommittedAndStartingAgainFinishes(): void
    {
        $now = CarbonImmutable::parse(self::NOW)->subDays(2);

        config()->set('sso.pruning.batch_size', 2);

        for ($row = 0; $row < 5; $row++) {
            $this->prunableRow(PruneKind::HANDOFF_CODES, $this->connection, $now);
        }

        $this->prunableRow(PruneKind::RATE_LIMITS, $this->connection, $now);

        $this->failStatement(self::onTable('delete', 'sso_handoff_codes'), 2);

        try {
            $this->pruner()->run();
            self::fail('A failed run reported success.');
        } catch (PruneFailedException $exception) {
            self::assertSame(1, $this->databaseFailuresFired());
            self::assertSame(PruneStatus::FAILED, $exception->report->status);
            self::assertSame(2, $exception->report->deleted(PruneKind::HANDOFF_CODES));
            self::assertSame(1, $exception->report->deleted(PruneKind::RATE_LIMITS));
            self::assertSame(['handoff_codes' => 'Illuminate\Database\QueryException'], $exception->report->failures);
            self::assertSame('The prune stopped on handoff_codes (Illuminate\Database\QueryException).', $exception->getMessage());
            self::assertTrue(self::isInjectedFailure($exception->getPrevious()));
        }

        self::assertCount(3, $this->prunableRowsLeft(PruneKind::HANDOFF_CODES));

        $again = $this->pruner()->run();

        self::assertSame(3, $again->deleted(PruneKind::HANDOFF_CODES));
        self::assertSame(PruneStatus::COMPLETE, $again->status);
        self::assertSame([], $this->prunableRowsLeft(PruneKind::HANDOFF_CODES));
    }

    /**
     * A failure among the selects stops that kind too, and two kinds failing
     * are both named, the first chained.
     *
     * @return void
     */
    public function testEveryKindThatFailedIsNamed(): void
    {
        $this->prunableRow(PruneKind::RATE_LIMITS, $this->connection, CarbonImmutable::parse(self::NOW));

        $this->failStatement(self::onTable('select', 'sso_authorization_requests'));
        $this->failStatement(self::onTable('delete', 'sso_rate_limits'));

        try {
            $this->pruner()->run();
            self::fail('A failed run reported success.');
        } catch (PruneFailedException $exception) {
            self::assertSame([
                'authorization_requests' => 'Illuminate\Database\QueryException',
                'rate_limits'            => 'Illuminate\Database\QueryException',
            ], $exception->report->failures);
            self::assertSame(
                'The prune stopped on authorization_requests (Illuminate\Database\QueryException), rate_limits (Illuminate\Database\QueryException).',
                $exception->getMessage(),
            );
            self::assertStringContainsString('select', (string) $exception->getPrevious()?->getMessage());
        }
    }

    /**
     * A failure raising the links version rolls back that connection's delete
     * too: the reservation is there for the next run, and nothing is counted.
     *
     * @return void
     */
    public function testAFailureRaisingTheVersionRollsBackTheDelete(): void
    {
        $this->reservationRow($this->connection, 901, CarbonImmutable::parse(self::NOW)->subMinute());

        $this->failStatement(self::onTable('update', 'sso_connections'));

        try {
            $this->pruner()->run();
            self::fail('A failed run reported success.');
        } catch (PruneFailedException $exception) {
            self::assertSame(0, $exception->report->deleted(PruneKind::RESERVATIONS));
        }

        self::assertSame(1, Link::query()->count());
        self::assertSame(0, $this->linksVersion($this->connection));

        self::assertSame(1, $this->pruner()->run()->deleted(PruneKind::RESERVATIONS));
        self::assertSame(1, $this->linksVersion($this->connection));
    }

    /**
     * Each connection's transaction in a batch of reservations commits alone: a
     * failure on a later one keeps the count, the deletes and the version of
     * the earlier, and leaves its own row for the next run, which reports it.
     *
     * @return void
     */
    public function testAFailureOnALaterConnectionKeepsWhatTheEarlierCommitted(): void
    {
        $now     = CarbonImmutable::parse(self::NOW)->subMinute();
        $other   = $this->makeConnection(['tenant_id' => 'tenant-2', 'protocol' => 'saml2']);
        $ordered = [$this->connection, $other];

        usort($ordered, static fn (Connection $left, Connection $right): int => strcmp($left->id, $right->id));

        [$first, $second] = $ordered;

        $this->reservationRow($first, 901, $now);
        $this->reservationRow($first, 902, $now);

        $left = $this->reservationRow($second, 903, $now)->id;

        $this->failStatement(self::onTable('update', 'sso_connections'), 2);

        try {
            $this->pruner()->run();
            self::fail('A failed run reported success.');
        } catch (PruneFailedException $exception) {
            self::assertSame(1, $this->databaseFailuresFired());
            self::assertSame(2, $exception->report->deleted(PruneKind::RESERVATIONS));
            self::assertSame(['reservations' => 'Illuminate\Database\QueryException'], $exception->report->failures);
        }

        self::assertSame([$left], array_values(Link::query()->pluck('id')->all()));
        self::assertSame(1, $this->linksVersion($first));
        self::assertSame(0, $this->linksVersion($second));

        $again = $this->pruner()->run();

        self::assertSame(1, $again->deleted(PruneKind::RESERVATIONS));
        self::assertSame(PruneStatus::COMPLETE, $again->status);
        self::assertSame(1, $this->linksVersion($first));
        self::assertSame(1, $this->linksVersion($second));
    }

    /**
     * Rows of `[what deadlocks, how many times, whether the kind then fails]`:
     * a statement a deadlock rolled back is tried three times in all, and the
     * transaction of a reservation with it.
     *
     * @return iterable<string, array{0: bool, 1: int, 2: bool}>
     */
    public static function provideDeadlocks(): iterable
    {
        yield 'a batch, tried again' => [false, 2, false];
        yield 'a batch, out of tries' => [false, 3, true];
        yield 'a reservation, tried again' => [true, 2, false];
        yield 'a reservation, out of tries' => [true, 3, true];
    }

    /**
     * A deadlock is tried again, at most three times in all, and only then
     * fails the kind.
     *
     * @param  bool  $reservation
     * @param  int  $times
     * @param  bool  $fails
     * @return void
     */
    #[DataProvider('provideDeadlocks')]
    public function testADeadlockIsTriedThreeTimesInAll(bool $reservation, int $times, bool $fails): void
    {
        $kind = $reservation ? PruneKind::RESERVATIONS : PruneKind::RATE_LIMITS;

        $this->prunableRow($kind, $this->connection, CarbonImmutable::parse(self::NOW));

        $this->deadlockStatement(self::onTable('delete', $reservation ? 'sso_links' : 'sso_rate_limits'), $times);

        $thrown = $this->refusalOfARun();

        self::assertSame($times, $this->databaseFailuresFired());
        self::assertSame($fails, $thrown instanceof PruneFailedException);
        self::assertCount($fails ? 1 : 0, $this->prunableRowsLeft($kind));
    }

    /**
     * A clock that goes back during a run reports a duration of none, never a
     * negative one.
     *
     * @return void
     */
    public function testAClockGoingBackReportsNoDuration(): void
    {
        $this->app?->instance(Clock::class, new TickingClock(self::NOW, -5));

        self::assertSame(0, $this->pruner()->run()->durationMilliseconds);
    }

    /**
     * Inside a transaction on the storage connection, a run refuses before
     * anything is read or deleted, and logs nothing.
     *
     * @return void
     */
    public function testRefusesAnOpenTransactionOnTheStorageConnection(): void
    {
        $this->prunableRow(PruneKind::RATE_LIMITS, $this->connection, CarbonImmutable::parse(self::NOW));

        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        $refusal = $this->refusalOfARun();

        $database->rollBack();

        self::assertInstanceOf(\LogicException::class, $refusal);
        self::assertSame('A prune runs outside any transaction on the storage and rate limit connections, so that each batch commits by itself.', $refusal->getMessage());

        self::assertSame(1, RateLimit::query()->count());
        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * With the counters on a connection of their own: they are pruned there,
     * none of it depends on the storage connection, a transaction open there
     * refuses the run as well, and the same rows go as `model:prune` would
     * take.
     *
     * @return void
     */
    public function testCountersLiveOnTheirOwnConnection(): void
    {
        config()->set('database.connections.counters', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);

        $this->dropRateLimits();

        config()->set('sso.rate_limits.connection', 'counters');

        $this->createRateLimits();

        $now = CarbonImmutable::parse(self::NOW);

        $this->prunableRow(PruneKind::RATE_LIMITS, $this->connection, $now);

        $kept = $this->prunableRow(PruneKind::RATE_LIMITS, $this->connection, $now->addSecond());

        $database = DB::connection('counters');

        $database->beginTransaction();

        $refusal = $this->refusalOfARun();

        self::assertSame(2, $database->table('sso_rate_limits')->count());

        $database->rollBack();

        self::assertInstanceOf(\LogicException::class, $refusal);

        self::assertSame(1, $this->pruner()->run()->deleted(PruneKind::RATE_LIMITS));
        self::assertSame([$kept], $this->prunableRowsLeft(PruneKind::RATE_LIMITS));
        self::assertFalse(Schema::hasTable('sso_rate_limits'));

        $this->dropRateLimits();

        config()->set('sso.rate_limits.connection');

        $this->createRateLimits();
    }

    /**
     * With the storage on a connection of its own and nothing on the default,
     * every kind goes, each version is raised, and every transaction of the run
     * is opened there, none on the default. A transaction open there refuses
     * the run. A failure raising the version rolls the delete back, which it
     * could not if the two were not in one transaction on that connection.
     *
     * @return void
     */
    public function testARunWorksOnAStorageConnectionOfItsOwn(): void
    {
        $now = CarbonImmutable::parse(self::NOW)->subDays(2);

        $this->dropPruningTables();

        config()->set('database.connections.store', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        config()->set('sso.storage.connection', 'store');

        $this->createPruningTables();

        try {

            $this->connection = $this->makeConnection(['protocol' => 'saml2']);

            foreach (PruneKind::cases() as $kind) {
                $this->prunableRow($kind, $this->connection, $now);
            }

            $database = DB::connection('store');

            $database->beginTransaction();

            $refusal = $this->refusalOfARun();

            $database->rollBack();

            self::assertInstanceOf(\LogicException::class, $refusal);

            $began = [];

            Event::listen(TransactionBeginning::class, static function (TransactionBeginning $event) use (&$began): void {
                $began[] = $event->connectionName;
            });

            self::assertSame(6, $this->pruner()->run()->total());
            self::assertSame(['store'], array_values(array_unique($began)));
            self::assertSame(0, Link::query()->count());
            self::assertSame(1, $this->linksVersion($this->connection));
            self::assertFalse(Schema::hasTable('sso_connections'));

            $this->reservationRow($this->connection, 901, $now);

            $this->failStatement(self::onTable('update', 'sso_connections'));

            try {
                $this->pruner()->run();
                self::fail('A failed run reported success.');
            } catch (PruneFailedException $exception) {
                self::assertSame(0, $exception->report->deleted(PruneKind::RESERVATIONS));
                self::assertTrue(self::isInjectedFailure($exception->getPrevious()));
            }

            self::assertSame(1, $database->table('sso_links')->count());
            self::assertSame(1, $this->linksVersion($this->connection));
        } finally {

            $this->dropPruningTables();

            config()->set('sso.storage.connection');

            $this->createPruningTables();
        }
    }

    /**
     * Every read is made on the write connection: with the read connection
     * unusable, the run goes on as ever.
     *
     * @return void
     */
    public function testReadsTheWriteConnection(): void
    {
        $this->prunableRow(PruneKind::RESERVATIONS, $this->connection, CarbonImmutable::parse(self::NOW));
        $this->prunableRow(PruneKind::RATE_LIMITS, $this->connection, CarbonImmutable::parse(self::NOW));

        DB::connection(StorageConnection::name())->setReadPdo(static function (): never {
            throw new \LogicException('The read connection was used.');
        });

        try {
            $report = $this->pruner()->run();
        } finally {
            DB::connection(StorageConnection::name())->setReadPdo(null);
        }

        self::assertSame(2, $report->total());
    }

    /**
     * Renamed tables are pruned under their names, with their indexes named
     * from them.
     *
     * @return void
     */
    public function testRenamedTablesArePruned(): void
    {
        $now = CarbonImmutable::parse(self::NOW)->subDays(2);

        $this->dropPruningTables();

        foreach (['single_use', 'rate_limits', 'connections', 'keys', 'domains', 'links', 'identity_guards', 'authorization_requests', 'handoff_codes'] as $section) {
            config()->set("sso.{$section}.table", "renamed_{$section}");
        }

        $this->createPruningTables();

        $this->connection = $this->makeConnection(['protocol' => 'saml2']);

        foreach (PruneKind::cases() as $kind) {
            $this->prunableRow($kind, $this->connection, $now);
        }

        self::assertSame(6, $this->pruner()->run()->total());
        self::assertSame(0, Link::query()->count());
        self::assertSame(1, $this->linksVersion($this->connection));

        $this->dropPruningTables();

        foreach (['single_use', 'rate_limits', 'connections', 'keys', 'domains', 'links', 'identity_guards', 'authorization_requests', 'handoff_codes'] as $section) {
            config()->set("sso.{$section}.table", StorageConnection::TABLES["{$section}.table"]);
        }

        $this->createPruningTables();
    }

    /**
     * A schema-qualified table is pruned where it lives.
     *
     * @return void
     */
    public function testASchemaQualifiedTableIsPruned(): void
    {
        $database = DB::connection();
        $driver   = $database->getDriverName();
        $schema   = 'sso_prune_schema';

        match ($driver) {
            'sqlite' => $database->statement("attach database ':memory:' as {$schema}"),
            'pgsql'  => $database->statement("create schema {$schema}"),
            default  => $database->statement("create database {$schema}"),
        };

        $table   = "{$schema}.counters";
        $grammar = $database->getQueryGrammar();

        $database->statement(sprintf(
            'create table %s (%s char(64) primary key, %s integer not null, %s %s not null)',
            $grammar->wrapTable($table),
            $grammar->wrap('key'),
            $grammar->wrap('hits'),
            $grammar->wrap('window_ends_at'),
            $driver === 'pgsql' ? 'timestamp(0)' : 'datetime',
        ));

        config()->set('sso.rate_limits.table', $table);

        try {

            $this->prunableRow(PruneKind::RATE_LIMITS, $this->connection, CarbonImmutable::parse(self::NOW));

            self::assertSame(1, $this->pruner()->run()->deleted(PruneKind::RATE_LIMITS));
            self::assertSame(0, $database->table($table)->count());
        } finally {

            config()->set('sso.rate_limits.table', 'sso_rate_limits');

            match ($driver) {
                'sqlite' => $database->statement("detach database {$schema}"),
                'pgsql'  => $database->statement("drop schema {$schema} cascade"),
                default  => $database->statement("drop database {$schema}"),
            };
        }
    }

    /**
     * Rows of `[what fails, the level, the outcome]`: how a run logs how it
     * ended.
     *
     * @return iterable<string, array{0: bool, 1: bool, 2: string, 3: string}>
     */
    public static function provideLogLines(): iterable
    {
        yield 'complete' => [false, false, 'info', 'complete'];
        yield 'incomplete' => [true, false, 'warning', 'incomplete'];
        yield 'failed' => [false, true, 'error', 'failed'];
    }

    /**
     * A run logs one line, at the level its end calls for, with the outcome,
     * the duration and the counts, and on a failure the kind and the class
     * alone: no identifier, no stored value, no message. It dispatches no
     * event.
     *
     * @param  bool  $capped
     * @param  bool  $fails
     * @param  string  $level
     * @param  string  $outcome
     * @return void
     */
    #[DataProvider('provideLogLines')]
    public function testARunLogsOneLineAndDispatchesNoEvent(bool $capped, bool $fails, string $level, string $outcome): void
    {
        $now = CarbonImmutable::parse(self::NOW)->subDays(2);

        $id = $this->prunableRow(PruneKind::AUTHORIZATION_REQUESTS, $this->connection, $now);

        $this->prunableRow(PruneKind::AUTHORIZATION_REQUESTS, $this->connection, $now);

        if ($capped) {
            config()->set('sso.pruning.max_rows_per_kind', 1);
        }

        if ($fails) {
            $this->failStatement(self::onTable('delete', 'sso_authorization_requests'));
        }

        try {
            $this->pruner()->run();
        } catch (PruneFailedException) {
            self::assertTrue($fails);
        }

        $records = $this->capturedLogRecords();

        self::assertCount(1, $records);
        self::assertSame(Pruner::LOG_MESSAGE, $records[0]['message']);
        self::assertSame($level, $records[0]['level']);
        self::assertSame($outcome, $records[0]['context']['outcome']);
        self::assertSame(0, $records[0]['context']['duration_ms']);
        self::assertSame(['outcome', 'now', 'duration_ms', 'deleted', 'incomplete', 'failures'], array_keys($records[0]['context']));
        self::assertSame($fails ? ['authorization_requests' => 'Illuminate\Database\QueryException'] : [], $records[0]['context']['failures']);
        self::assertSame($capped ? ['authorization_requests'] : [], $records[0]['context']['incomplete']);
        self::assertSame(array_map(static fn (PruneKind $kind): string => $kind->value, PruneKind::cases()), array_keys($records[0]['context']['deleted']));
        $this->assertNothingLoggedContains($id, $this->connection->id, self::INJECTED_FAILURE, 'sso_authorization_requests');
        $this->assertNoEvents();
    }

    /**
     * What a report says of itself, as it is encoded.
     *
     * @return void
     */
    public function testAReportEncodesInSnakeCaseWithItsInstantInUtc(): void
    {
        $this->prunableRow(PruneKind::RATE_LIMITS, $this->connection, CarbonImmutable::parse(self::NOW));

        self::assertSame([
            'outcome'     => 'complete',
            'now'         => '2026-11-01T12:00:00Z',
            'duration_ms' => 0,
            'deleted'     => ['authorization_requests' => 0, 'handoff_codes' => 0, 'single_use_keys' => 0, 'reservations' => 0, 'pending_claims' => 0, 'rate_limits' => 1],
            'incomplete'  => [],
            'failures'    => [],
        ], $this->pruner()->run()->jsonSerialize());
    }

    /**
     * `model:prune` and a run take the same keys and counters on each side of
     * the boundary, so the two entry points cannot disagree.
     *
     * @return void
     */
    public function testAgreesWithTheModelPruneEntryPoints(): void
    {
        $now = CarbonImmutable::parse(self::NOW);

        foreach ([PruneKind::SINGLE_USE_KEYS, PruneKind::RATE_LIMITS] as $kind) {
            $this->prunableRow($kind, $this->connection, $now);
            $this->prunableRow($kind, $this->connection, $now->addSecond());
        }

        $keysBefore     = SingleUseKey::query()->count();
        $countersBefore = RateLimit::query()->count();
        $byModelKeys    = (new SingleUseKey)->prunable()->pluck('id')->all();
        $byModelCounter = (new RateLimit)->prunable()->pluck('key')->all();

        $this->pruner()->run();

        self::assertSame(2, $keysBefore);
        self::assertSame(2, $countersBefore);
        self::assertCount(1, $byModelKeys);
        self::assertCount(1, $byModelCounter);
        self::assertFalse(SingleUseKey::query()->whereKey($byModelKeys)->exists());
        self::assertFalse(RateLimit::query()->whereKey($byModelCounter)->exists());
        self::assertSame(1, SingleUseKey::query()->count());
        self::assertSame(1, RateLimit::query()->count());
    }

    /**
     * The settings' default batch is what a run uses when nothing is set.
     *
     * @return void
     */
    public function testNothingSetTakesTheDefaults(): void
    {
        config()->set('sso.pruning', []);

        $this->prunableRow(PruneKind::AUTHORIZATION_REQUESTS, $this->connection, CarbonImmutable::parse(self::NOW)->subSeconds(PruneSettings::DEFAULT_RETENTION_SECONDS));

        self::assertSame(1, $this->pruner()->run()->total());
    }

    /**
     * What a run throws, if anything.
     *
     * @return ?\Throwable
     */
    private function refusalOfARun(): ?\Throwable
    {
        try {
            $this->pruner()->run();
        } catch (\Throwable $exception) {
            return $exception;
        }

        return null;
    }

    /**
     * Run the callback once, before the first delete sent on the storage
     * connection, as another server's change between the select and the delete.
     *
     * @param  \Closure(): void  $callback
     * @return void
     */
    private function beforeTheFirstDelete(\Closure $callback): void
    {
        $fired = false;

        foreach (array_unique([StorageConnection::name(), StorageConnection::forRateLimits()]) as $name) {
            DB::connection($name)->beforeExecuting(static function (string $query) use ($callback, &$fired): void {

                if ($fired || !str_starts_with(strtolower($query), 'delete')) {
                    return;
                }

                $fired = true;

                $callback();
            });
        }
    }

    /**
     * Make the row of the kind no longer eligible, as a renewal, a recording,
     * an activation or a verification does.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @param  string  $key
     * @param  \Carbon\CarbonImmutable  $now
     * @return void
     */
    private function renew(PruneKind $kind, string $key, CarbonImmutable $now): void
    {
        $later = $now->addHour()->format('Y-m-d H:i:s');

        match ($kind) {
            PruneKind::AUTHORIZATION_REQUESTS => AuthorizationRequest::query()->whereKey($key)->update(['expires_at' => $later]),
            PruneKind::HANDOFF_CODES          => HandoffCode::query()->whereKey($key)->update(['expires_at' => $later]),
            PruneKind::SINGLE_USE_KEYS        => SingleUseKey::query()->whereKey($key)->update(['expires_at' => $later]),
            PruneKind::RESERVATIONS           => Link::query()->whereKey($key)->update(['state' => LinkState::ACTIVE->value, 'reservation_expires_at' => null]),
            PruneKind::PENDING_CLAIMS         => Domain::query()->whereKey($key)->update(['state' => DomainState::VERIFIED->value]),
            PruneKind::RATE_LIMITS            => RateLimit::query()->whereKey($key)->update(['window_ends_at' => $later]),
        };
    }

    /**
     * A counter of the key given, of the column's full width, whose window ends
     * at the instant.
     *
     * @param  string  $letter
     * @param  \Carbon\CarbonImmutable  $at
     * @return string
     */
    private function counter(string $letter, CarbonImmutable $at): string
    {
        $model = new RateLimit;
        $key   = str_repeat($letter, 64);

        DB::connection($model->getConnectionName())->table($model->getTable())->insert(['key' => $key, 'hits' => 1, 'window_ends_at' => $at->format('Y-m-d H:i:s')]);

        return $key;
    }

    /**
     * The target of the kind at the clock's instant.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @return \SineMacula\Laravel\Sso\Pruning\PruneTarget
     */
    private function target(PruneKind $kind): PruneTarget
    {
        $now = CarbonImmutable::parse(self::NOW);

        foreach (PruneTarget::all($now, $now->subSeconds(self::RETENTION)) as $target) {
            if ($target->kind === $kind) {
                return $target;
            }
        }

        self::fail('No target of the kind.');
    }

    /**
     * The connection's links version as stored now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return int
     */
    private function linksVersion(Connection $connection): int
    {
        return Connection::query()->whereKey($connection->id)->sole()->links_version;
    }

    /**
     * The pruner.
     *
     * @return \SineMacula\Laravel\Sso\Pruning\Pruner
     */
    private function pruner(): Pruner
    {
        return app(Pruner::class);
    }

    /**
     * Create every table a run reads.
     *
     * @return void
     */
    private function createPruningTables(): void
    {
        $this->createConnectionTables();
        $this->createDomainsTable();
        $this->createFlowTables();
        self::shipped(self::SINGLE_USE_MIGRATION)->up(); // @phpstan-ignore method.notFound
        $this->createRateLimits();
    }

    /**
     * Drop every table a run reads.
     *
     * @return void
     */
    private function dropPruningTables(): void
    {
        $this->dropRateLimits();
        self::shipped(self::SINGLE_USE_MIGRATION)->down(); // @phpstan-ignore method.notFound
        $this->dropFlowTables();
        $this->dropDomainsTable();
        $this->dropConnectionTables();
    }

    /**
     * Create the counters' table where it is configured to be.
     *
     * @return void
     */
    private function createRateLimits(): void
    {
        self::shipped(self::RATE_LIMITS_MIGRATION)->up(); // @phpstan-ignore method.notFound
    }

    /**
     * Drop the counters' table from where it is configured to be.
     *
     * @return void
     */
    private function dropRateLimits(): void
    {
        self::shipped(self::RATE_LIMITS_MIGRATION)->down(); // @phpstan-ignore method.notFound
    }

    /**
     * The shipped migration at the path.
     *
     * @param  string  $path
     * @return object
     */
    private static function shipped(string $path): object
    {
        return require dirname(__DIR__, 3) . $path;
    }
}
