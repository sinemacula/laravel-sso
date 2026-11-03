<?php

declare(strict_types = 1);

namespace Tests\Integration\Pruning;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneKind;
use SineMacula\Laravel\Sso\Pruning\Pruner;
use SineMacula\Laravel\Sso\Pruning\PruneTarget;
use Tests\Concerns\MakesPrunableRows;
use Tests\Concerns\RacesProcesses;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesEveryTable;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Races runs of the clean-up across processes, each with its own database
 * connection, on PostgreSQL and MySQL (SSO-11.11): however they interleave,
 * every eligible row goes exactly once, the counts of all the runs adding up to
 * the rows there were, nothing else goes, nobody fails, and the links version
 * rises for each connection reservations went from.
 *
 * A run refuses a caller's transaction, so each racer runs plainly; the refusal
 * has its test in `PrunerTest`. Skipped on SQLite, whose in-memory database
 * each process would have to itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Pruner::class)]
#[CoversClass(PruneTarget::class)]
final class ConcurrentPrunersTest extends TestCase
{
    use MakesPrunableRows, RacesProcesses, UsesConnections, UsesDomains, UsesEveryTable, UsesFlowTables;

    /** @var int Processes racing. */
    private const int PROCESSES = 4;

    /** @var int Eligible rows of each kind. */
    private const int ROWS = 12;

    /** @var string The instant the clock holds. */
    private const string NOW = '2026-11-01T12:00:00Z';

    /** @var list<\SineMacula\Laravel\Sso\Models\Connection> The connections the rows alternate between. */
    private array $connections = [];

    /** @var bool Whether the tables were made. */
    private bool $created = false;

    /**
     * Skip where processes cannot share the database; bind a fixed clock, and
     * create the tables and the connections.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpRace();

        $this->app?->instance(Clock::class, new FixedClock(self::NOW));

        $this->createEveryTable();

        $this->created     = true;
        $this->connections = [$this->makeConnection(['protocol' => 'saml2']), $this->makeConnection(['tenant_id' => 'tenant-2', 'protocol' => 'saml2'])];
    }

    /**
     * Remove what the race used and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->tearDownRace();

        if ($this->created) {
            $this->dropEveryTable();
        }

        parent::tearDown();
    }

    /**
     * Runs racing over the same rows delete each exactly once between them, and
     * leave standing what was never eligible.
     *
     * @return void
     */
    public function testRacingRunsDeleteEachRowOnce(): void
    {
        config()->set('sso.pruning.batch_size', 3);

        $kept = [];
        $at   = CarbonImmutable::parse(self::NOW)->subDays(2);

        foreach (PruneKind::cases() as $kind) {

            for ($row = 0; $row < self::ROWS; $row++) {
                $this->prunableRow($kind, $this->connections[$row % 2], $at->addSeconds($row % 3));
            }

            $kept[$kind->value] = $this->prunableRow($kind, $this->connections[0], CarbonImmutable::parse(self::NOW)->addHour());
        }

        $racers = array_fill(0, self::PROCESSES, static fn (): array => app(Pruner::class)->run()->deleted);

        $results = $this->assertRacersSucceeded($this->race($racers));

        self::assertCount(self::PROCESSES, $results);

        foreach (PruneKind::cases() as $kind) {
            self::assertSame(self::ROWS, array_sum(array_column($results, $kind->value)), "The counts of {$kind->value} do not add up.");
            self::assertSame([$kept[$kind->value]], $this->prunableRowsLeft($kind));
        }

        foreach ($this->connections as $connection) {
            self::assertGreaterThanOrEqual(1, Connection::query()->findOrFail($connection->id)->links_version);
        }
    }
}
