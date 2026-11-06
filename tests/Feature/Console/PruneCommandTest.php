<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Console\PruneCommand;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneKind;
use Tests\Concerns\FailsDatabaseStatements;
use Tests\Concerns\MakesPrunableRows;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Logging\UnwritableLogHandler;
use Tests\TestCase;

/**
 * Feature tests for `sso:prune` (SSO-11.11): the counts and how the run ended
 * on one line, exit 0 on complete and incomplete with the way on said,
 * `--drain`, and exit 1 on a failure, printing what committed and naming the
 * kind and the exception by class alone, and on a summary that could not be
 * logged, printing the counts all the same.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneCommand::class)]
final class PruneCommandTest extends TestCase
{
    use FailsDatabaseStatements, MakesPrunableRows, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The instant the clock holds. */
    private const string NOW = '2026-11-01T12:00:00Z';

    /**
     * Bind a fixed clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock(self::NOW));

        $this->usePackageTables();
    }

    /**
     * With nothing eligible, one line says so, and it passes.
     *
     * @return void
     */
    public function testWithNothingEligiblePrintsTheCountsAlone(): void
    {
        [$code, $output] = $this->prune();

        self::assertSame(0, $code);
        self::assertSame(['Pruned (complete): authorization_requests 0, handoff_codes 0, single_use_keys 0, reservations 0, pending_claims 0, rate_limits 0'], $output);
    }

    /**
     * What went is counted under its kind.
     *
     * @return void
     */
    public function testPrintsTheCountOfEachKind(): void
    {
        $connection = $this->makeConnection();
        $at         = CarbonImmutable::parse(self::NOW)->subDays(2);

        foreach (PruneKind::cases() as $index => $kind) {
            for ($row = 0; $row <= $index; $row++) {
                $this->prunableRow($kind, $connection, $at);
            }
        }

        [$code, $output] = $this->prune();

        self::assertSame(0, $code);
        self::assertSame(['Pruned (complete): authorization_requests 1, handoff_codes 2, single_use_keys 3, reservations 4, pending_claims 5, rate_limits 6'], $output);
    }

    /**
     * A run stopped by the work cap passes, says it is incomplete, and says how
     * to go on; `--drain` finishes.
     *
     * @return void
     */
    public function testAnIncompleteRunPassesAndADrainFinishes(): void
    {
        $connection = $this->makeConnection();
        $at         = CarbonImmutable::parse(self::NOW)->subDays(2);

        config()->set('sso.pruning.max_rows_per_kind', 1);

        for ($row = 0; $row < 3; $row++) {
            $this->prunableRow(PruneKind::RATE_LIMITS, $connection, $at);
        }

        [$code, $output] = $this->prune();

        self::assertSame(0, $code);
        self::assertSame([
            'Pruned (incomplete): authorization_requests 0, handoff_codes 0, single_use_keys 0, reservations 0, pending_claims 0, rate_limits 1',
            'More is eligible: the next run goes on, or run sso:prune --drain.',
        ], $output);

        [$code, $output] = $this->prune(['--drain' => true]);

        self::assertSame(0, $code);
        self::assertSame(['Pruned (complete): authorization_requests 0, handoff_codes 0, single_use_keys 0, reservations 0, pending_claims 0, rate_limits 2'], $output);
    }

    /**
     * A failure exits non-zero, printing what committed and naming the kind and
     * the exception by class alone: no SQL, no value, no message.
     *
     * @return void
     */
    public function testAFailureExitsNonZeroAndKeepsWhatCommitted(): void
    {
        $connection = $this->makeConnection();
        $at         = CarbonImmutable::parse(self::NOW)->subDays(2);
        $id         = $this->prunableRow(PruneKind::HANDOFF_CODES, $connection, $at);

        $this->prunableRow(PruneKind::RATE_LIMITS, $connection, $at);

        $this->failStatement(self::onTable('delete', 'sso_handoff_codes'));

        [$code, $output] = $this->prune();

        self::assertSame(1, $code);
        self::assertSame([
            'Pruned (failed): authorization_requests 0, handoff_codes 0, single_use_keys 0, reservations 0, pending_claims 0, rate_limits 1',
            'The prune of handoff_codes stopped on Illuminate\Database\QueryException.',
        ], $output);
        self::assertStringNotContainsString($id, implode("\n", $output));
        self::assertStringNotContainsString(self::INJECTED_FAILURE, implode("\n", $output));
    }

    /**
     * A summary the logger refuses after a run that deleted everything exits
     * non-zero, printing the counts and naming the logger's exception by class
     * alone; what was deleted stays deleted.
     *
     * @return void
     */
    public function testALogThatCannotBeWrittenStillPrintsTheCounts(): void
    {
        $connection = $this->makeConnection();
        $at         = CarbonImmutable::parse(self::NOW)->subDays(2);

        $this->prunableRow(PruneKind::HANDOFF_CODES, $connection, $at);
        $this->prunableRow(PruneKind::RATE_LIMITS, $connection, $at);

        UnwritableLogHandler::configure();

        [$code, $output] = $this->prune();

        self::assertSame(1, $code);
        self::assertSame([
            'Pruned (complete): authorization_requests 0, handoff_codes 1, single_use_keys 0, reservations 0, pending_claims 0, rate_limits 1',
            'The prune\'s log line failed on UnexpectedValueException.',
        ], $output);
        self::assertSame([], $this->prunableRowsLeft(PruneKind::HANDOFF_CODES));
        self::assertSame([], $this->prunableRowsLeft(PruneKind::RATE_LIMITS));
    }

    /**
     * A summary the logger refuses after a kind failed exits non-zero, printing
     * what committed, the kind's failure, and the logger's, each by class
     * alone.
     *
     * @return void
     */
    public function testALogThatCannotBeWrittenStillNamesTheFailure(): void
    {
        $connection = $this->makeConnection();
        $at         = CarbonImmutable::parse(self::NOW)->subDays(2);
        $id         = $this->prunableRow(PruneKind::HANDOFF_CODES, $connection, $at);

        $this->prunableRow(PruneKind::RATE_LIMITS, $connection, $at);

        $this->failStatement(self::onTable('delete', 'sso_handoff_codes'));

        UnwritableLogHandler::configure();

        [$code, $output] = $this->prune();

        self::assertSame(1, $code);
        self::assertSame([
            'Pruned (failed): authorization_requests 0, handoff_codes 0, single_use_keys 0, reservations 0, pending_claims 0, rate_limits 1',
            'The prune of handoff_codes stopped on Illuminate\Database\QueryException.',
            'The prune\'s log line failed on UnexpectedValueException.',
        ], $output);
        self::assertSame([$id], $this->prunableRowsLeft(PruneKind::HANDOFF_CODES));
        self::assertSame([], $this->prunableRowsLeft(PruneKind::RATE_LIMITS));
    }

    /**
     * A refusal, inside a transaction, exits non-zero by class alone.
     *
     * @return void
     */
    public function testARefusalExitsNonZeroByClassAlone(): void
    {
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        try {
            [$code, $output] = $this->prune();
        } finally {
            $database->rollBack();
        }

        self::assertSame(1, $code);
        self::assertSame(['The prune stopped on LogicException.'], $output);
    }

    /**
     * Run the command and answer its exit code and output lines.
     *
     * @param  array<string, mixed>  $options
     * @return array{0: int, 1: list<string>}
     */
    private function prune(array $options = []): array
    {
        $code   = Artisan::call('sso:prune', $options);
        $output = array_values(array_filter(explode("\n", trim(Artisan::output())), static fn (string $line): bool => $line !== ''));

        return [$code, $output];
    }
}
