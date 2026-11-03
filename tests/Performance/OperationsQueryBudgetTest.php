<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Models\RateLimit;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneKind;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneStatus;
use SineMacula\Laravel\Sso\Pruning\Pruner;
use SineMacula\Laravel\Sso\Pruning\PruneReport;
use SineMacula\Laravel\Sso\Pruning\PruneTarget;
use Tests\Concerns\MakesPrunableRows;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;

/**
 * Query budgets for `Pruning\Pruner` (SSO-11.11), with the counters on a
 * connection of their own, so each budget says which statement went where:
 *
 * - each kind costs at least one candidate select, so a run with nothing
 *   eligible is six selects, five on the storage connection and one on the
 *   counters', and deletes nothing;
 * - a page is one select and a batch one delete: a full batch is followed by
 *   the next page's select, whether that finds a final partial batch or nothing;
 * - a kind stopped at its work cap by a full batch costs one probe select more,
 *   and a kind stopped by a partial batch, or a drain, none: only that probe
 *   says whether a run is incomplete;
 * - a batch of reservations costs, for each of its connections, the
 *   connection's locking read, one delete, and one update of its links version
 *   when the delete took a row; nothing else on the batch is locked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Pruner::class)]
#[CoversClass(PruneTarget::class)]
#[CoversClass(ReservationWithdrawal::class)]
final class OperationsQueryBudgetTest extends PerformanceContractTestCase
{
    use MakesPrunableRows, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var int How many of the kinds live on the storage connection. */
    private const int STORAGE_KINDS = 5;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the rows belong to. */
    private Connection $connection;

    /** @var \Carbon\CarbonImmutable An instant before the clock's now by more than the retention. */
    private CarbonImmutable $past;

    /**
     * Move the counters to their own connection, send the run's log line
     * nowhere, and make a connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->useSeparateCounters();

        config()->set('sso.logging.channel', 'null');

        $this->connection = $this->makeConnection();
        $this->past       = $this->clock->now()->subDays(2);
    }

    /**
     * A run with nothing eligible is one candidate select of each kind, each on
     * its own connection, and no delete.
     *
     * @return void
     */
    public function testAnEmptyRunIsOneSelectOfEachKind(): void
    {
        $report = $this->assertQueryBudget(self::STORAGE_KINDS, 0, fn (): PruneReport => $this->runPruner(), 1, 0);

        self::assertSame(PruneStatus::COMPLETE, $report->status);
        self::assertSame(0, $report->total());
        $this->assertTablesInTurn([new AuthorizationRequest, new HandoffCode, new SingleUseKey, new Link, new Domain]);
        $this->assertCountersKeptApart();
    }

    /**
     * Rows of `[kind]`: each kind pruned one statement at a time, on the
     * storage connection.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind}>
     */
    public static function provideStorageKinds(): iterable
    {
        yield 'authorisation requests' => [PruneKind::AUTHORIZATION_REQUESTS];
        yield 'handoff codes' => [PruneKind::HANDOFF_CODES];
        yield 'single-use keys' => [PruneKind::SINGLE_USE_KEYS];
        yield 'pending claims' => [PruneKind::PENDING_CLAIMS];
    }

    /**
     * A full batch and a final partial batch are the select of each page and
     * one delete of each batch, in that order; the other kinds cost a select
     * each.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @return void
     */
    #[DataProvider('provideStorageKinds')]
    public function testAFullBatchThenAPartialBatch(PruneKind $kind): void
    {
        config()->set('sso.pruning.batch_size', 2);

        $this->rowsOf($kind, 3);

        $report = $this->assertQueryBudget(6, 2, fn (): PruneReport => $this->runPruner(), 1, 0);

        self::assertSame(3, $report->deleted($kind));
        self::assertSame(PruneStatus::COMPLETE, $report->status);
        self::assertSame(self::verbsOf($kind, ['select', 'delete', 'select', 'delete']), self::verbs($this->statementsSent()));
        self::assertSame(['select'], self::verbs($this->counterStatementsSent()));
    }

    /**
     * Full batches alone end with one more select, which finds nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @return void
     */
    #[DataProvider('provideStorageKinds')]
    public function testFullBatchesEndWithAnEmptyPage(PruneKind $kind): void
    {
        config()->set('sso.pruning.batch_size', 2);

        $this->rowsOf($kind, 4);

        $report = $this->assertQueryBudget(7, 2, fn (): PruneReport => $this->runPruner(), 1, 0);

        self::assertSame(4, $report->deleted($kind));
        self::assertSame(self::verbsOf($kind, ['select', 'delete', 'select', 'delete', 'select']), self::verbs($this->statementsSent()));
    }

    /**
     * Counters are selected and deleted on their own connection, and nothing of
     * theirs reaches the storage connection.
     *
     * @return void
     */
    public function testCountersArePrunedOnTheirOwnConnection(): void
    {
        config()->set('sso.pruning.batch_size', 2);

        $this->rowsOf(PruneKind::RATE_LIMITS, 3);

        $report = $this->assertQueryBudget(self::STORAGE_KINDS, 0, fn (): PruneReport => $this->runPruner(), 2, 2);

        self::assertSame(3, $report->deleted(PruneKind::RATE_LIMITS));
        self::assertSame(['select', 'delete', 'select', 'delete'], self::verbs($this->counterStatementsSent()));
        $this->assertCountersKeptApart();
    }

    /**
     * Rows of `[cap, batch, rows, selects, deletes, deleted, status, drain]`:
     * how a kind's turn ends at its work cap, and what it costs. The probe is
     * the select that follows the last delete of a turn the cap ended on a full
     * batch: its `limit` is 1.
     *
     * @return iterable<string, array{0: int, 1: int, 2: int, 3: int, 4: int, 5: int, 6: \SineMacula\Laravel\Sso\Pruning\Enums\PruneStatus, 7: bool}>
     */
    public static function provideWorkCaps(): iterable
    {
        $complete   = PruneStatus::COMPLETE;
        $incomplete = PruneStatus::INCOMPLETE;

        yield 'the cap reached with more eligible' => [2, 2, 3, 2, 1, 2, $incomplete, false];
        yield 'the cap landing exactly on a batch' => [2, 2, 2, 2, 1, 2, $complete, false];
        yield 'the cap landing exactly inside a batch' => [3, 2, 3, 3, 2, 3, $complete, false];
        yield 'the cap inside a batch with more eligible' => [3, 2, 4, 3, 2, 3, $incomplete, false];
        yield 'a cap of one, with nothing more' => [1, 2, 1, 2, 1, 1, $complete, false];
        yield 'a cap of one, with more eligible' => [1, 2, 2, 2, 1, 1, $incomplete, false];
        yield 'under the cap, a final partial batch' => [10, 2, 3, 2, 2, 3, $complete, false];
        yield 'under the cap, one row short of it' => [3, 2, 2, 2, 1, 2, $complete, false];
        yield 'under the cap, a full batch and an empty page' => [10, 2, 2, 2, 1, 2, $complete, false];
        yield 'a drain goes past the cap, with no probe' => [2, 2, 3, 2, 2, 3, $complete, true];
    }

    /**
     * Each way a storage kind's turn ends at its work cap is the select and the
     * delete of each batch, and the probe only when the cap ended it on a full
     * batch.
     *
     * @param  int  $cap
     * @param  int  $batch
     * @param  int  $rows
     * @param  int  $selects
     * @param  int  $deletes
     * @param  int  $deleted
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneStatus  $status
     * @param  bool  $drain
     * @return void
     */
    #[DataProvider('provideWorkCaps')]
    public function testTheWorkCapOnTheStorageConnection(int $cap, int $batch, int $rows, int $selects, int $deletes, int $deleted, PruneStatus $status, bool $drain): void
    {
        config()->set('sso.pruning.max_rows_per_kind', $cap);
        config()->set('sso.pruning.batch_size', $batch);

        $this->rowsOf(PruneKind::HANDOFF_CODES, $rows);

        $report = $this->assertQueryBudget(self::STORAGE_KINDS - 1 + $selects, $deletes, fn (): PruneReport => $this->runPruner($drain), 1, 0);

        self::assertSame($deleted, $report->deleted(PruneKind::HANDOFF_CODES));
        self::assertSame($status, $report->status);
        self::assertSame($status === PruneStatus::INCOMPLETE ? [PruneKind::HANDOFF_CODES] : [], $report->incomplete);
    }

    /**
     * The same on the counters' connection.
     *
     * @param  int  $cap
     * @param  int  $batch
     * @param  int  $rows
     * @param  int  $selects
     * @param  int  $deletes
     * @param  int  $deleted
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneStatus  $status
     * @param  bool  $drain
     * @return void
     */
    #[DataProvider('provideWorkCaps')]
    public function testTheWorkCapOnTheCountersConnection(int $cap, int $batch, int $rows, int $selects, int $deletes, int $deleted, PruneStatus $status, bool $drain): void
    {
        config()->set('sso.pruning.max_rows_per_kind', $cap);
        config()->set('sso.pruning.batch_size', $batch);

        $this->rowsOf(PruneKind::RATE_LIMITS, $rows);

        $report = $this->assertQueryBudget(self::STORAGE_KINDS, 0, fn (): PruneReport => $this->runPruner($drain), $selects, $deletes);

        self::assertSame($deleted, $report->deleted(PruneKind::RATE_LIMITS));
        self::assertSame($status, $report->status);
    }

    /**
     * The probe asks for one row, after a page that asked for the batch.
     *
     * @return void
     */
    public function testTheProbeAsksForOneRow(): void
    {
        config()->set('sso.pruning.max_rows_per_kind', 2);
        config()->set('sso.pruning.batch_size', 2);

        $this->rowsOf(PruneKind::RATE_LIMITS, 3);

        $this->assertQueryBudget(self::STORAGE_KINDS, 0, fn (): PruneReport => $this->runPruner(), 2, 1);

        $sent = $this->counterStatementsSent();

        self::assertSame(['select', 'delete', 'select'], self::verbs($sent));
        self::assertStringEndsWith('limit 2', $sent[0]);
        self::assertStringEndsWith('limit 1', $sent[2]);
    }

    /**
     * A batch of reservations of one connection is the page's select, the
     * connection's lock, one delete and one update, batch after batch.
     *
     * @return void
     */
    public function testReservationsCostALockADeleteAndAnUpdateForEachBatch(): void
    {
        config()->set('sso.pruning.batch_size', 2);

        $this->rowsOf(PruneKind::RESERVATIONS, 3);

        $report = $this->assertQueryBudget(8, 4, fn (): PruneReport => $this->runPruner(), 1, 0);

        self::assertSame(3, $report->deleted(PruneKind::RESERVATIONS));
        self::assertSame(2, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
        self::assertSame(
            self::verbsOf(PruneKind::RESERVATIONS, ['select', 'select', 'delete', 'update', 'select', 'select', 'delete', 'update']),
            self::verbs($this->statementsSent()),
        );
    }

    /**
     * A batch of reservations of two connections is one select, then a lock, a
     * delete and an update for each.
     *
     * @return void
     */
    public function testReservationsCostALockADeleteAndAnUpdateForEachConnection(): void
    {
        $other = $this->makeConnection(['tenant_id' => 'tenant-2']);

        $this->rowsOf(PruneKind::RESERVATIONS, 2);
        $this->reservationRow($other, 900, $this->past);

        $report = $this->assertQueryBudget(7, 4, fn (): PruneReport => $this->runPruner(), 1, 0);

        self::assertSame(3, $report->deleted(PruneKind::RESERVATIONS));
        self::assertSame(1, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
        self::assertSame(1, Connection::query()->whereKey($other->id)->sole()->links_version);
    }

    /**
     * With nothing of those named still eligible, a withdrawal is the lock and
     * the delete, and raises no version.
     *
     * @return void
     */
    public function testAWithdrawalThatTookNothingRaisesNoVersion(): void
    {
        $live   = $this->reservationRow($this->connection, 901, $this->clock->now()->addHour());
        $cutoff = UtcDateTime::format(new Link, $this->clock->now());

        $deleted = $this->assertQueryBudget(1, 1, fn (): int => ReservationWithdrawal::expired($this->connection->id, [$live->id], $cutoff));

        self::assertSame(0, $deleted);
        self::assertSame(0, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
        self::assertSame(['select', 'delete'], self::verbs($this->statementsSent()));
    }

    /**
     * A reservation whose connection is gone is the lock that finds nothing,
     * the delete, and the update that touches no row.
     *
     * @return void
     */
    public function testAWithdrawalWhoseConnectionIsGoneStillDeletes(): void
    {
        $row    = $this->reservationRow($this->connection, 902, $this->past);
        $gone   = '01jbz0000000000000000000zz';
        $cutoff = UtcDateTime::format(new Link, $this->clock->now());

        Link::query()->whereKey($row->id)->update(['connection_id' => $gone]);

        $deleted = $this->assertQueryBudget(1, 2, static fn (): int => ReservationWithdrawal::expired($gone, [$row->id], $cutoff));

        self::assertSame(1, $deleted);
        self::assertSame(['select', 'delete', 'update'], self::verbs($this->statementsSent()));
    }

    /**
     * One row of every kind is a select and a delete of each, a lock and an
     * update beside the reservation's, and the counter's two statements on its
     * own connection alone.
     *
     * @return void
     */
    public function testEachStatementGoesToItsConnection(): void
    {
        foreach (PruneKind::cases() as $kind) {
            $this->rowsOf($kind, 1);
        }

        $report = $this->assertQueryBudget(6, 6, fn (): PruneReport => $this->runPruner(), 1, 1);

        self::assertSame(6, $report->total());
        self::assertSame(['select', 'delete'], self::verbs($this->counterStatementsSent()));
        $this->assertCountersKeptApart();
    }

    /**
     * Make that many eligible rows of the kind in the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @param  int  $rows
     * @return void
     */
    private function rowsOf(PruneKind $kind, int $rows): void
    {
        for ($row = 0; $row < $rows; $row++) {
            $this->prunableRow($kind, $this->connection, $this->past);
        }
    }

    /**
     * Run the pruner.
     *
     * @param  bool  $drain
     * @return \SineMacula\Laravel\Sso\Pruning\PruneReport
     */
    private function runPruner(bool $drain = false): PruneReport
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(Pruner::class)->run($drain);
    }

    /**
     * Assert the storage statements of the last budget went to the models'
     * tables, one each, in the order given.
     *
     * @param  list<\SineMacula\Laravel\Sso\Models\SsoModel>  $models
     * @return void
     */
    private function assertTablesInTurn(array $models): void
    {
        $grammar = DB::connection()->getQueryGrammar();
        $sent    = $this->statementsSent();

        self::assertCount(count($models), $sent);

        foreach ($models as $index => $model) {
            self::assertStringContainsString($grammar->wrapTable($model->getTable()), $sent[$index]);
        }
    }

    /**
     * Assert every statement of the counters' connection in the last budget
     * named the counters' table, and none of the storage connection's did.
     *
     * @return void
     */
    private function assertCountersKeptApart(): void
    {
        $counters = DB::connection(self::COUNTERS)->getQueryGrammar()->wrapTable((new RateLimit)->getTable());

        self::assertNotSame([], $this->counterStatementsSent());

        foreach ($this->counterStatementsSent() as $sql) {
            self::assertStringContainsString($counters, $sql);
        }

        foreach ($this->statementsSent() as $sql) {
            self::assertStringNotContainsString($counters, $sql);
        }
    }

    /**
     * The first word of each statement, in lower case.
     *
     * @param  list<string>  $sent
     * @return list<string>
     */
    private static function verbs(array $sent): array
    {
        return array_map(static fn (string $sql): string => strtolower(strtok(ltrim($sql), ' ') ?: ''), $sent);
    }

    /**
     * What a run sends on the storage connection when the kind's turn sends the
     * statements given and every other storage kind's the one select.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @param  list<string>  $turn
     * @return list<string>
     */
    private static function verbsOf(PruneKind $kind, array $turn): array
    {
        $verbs = [];

        foreach (PruneKind::cases() as $case) {
            if ($case === PruneKind::RATE_LIMITS) {
                continue;
            }

            $verbs = [...$verbs, ...($case === $kind ? $turn : ['select'])];
        }

        return $verbs;
    }
}
