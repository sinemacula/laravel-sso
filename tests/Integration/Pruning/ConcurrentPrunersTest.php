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
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Races pruner runs across processes on PostgreSQL and MySQL.
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
    use MakesPrunableRows, RacesProcesses, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var int Processes racing. */
    private const int PROCESSES = 4;

    /** @var int Eligible rows of each kind. */
    private const int ROWS = 12;

    /** @var string The instant the clock holds. */
    private const string NOW = '2026-11-01T12:00:00Z';

    /** @var list<\SineMacula\Laravel\Sso\Models\Connection> The connections the rows alternate between. */
    private array $connections = [];

    /**
     * Skip where processes cannot share the database; bind a fixed clock and
     * create the tables and connections.
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

        $this->usePackageTables();

        $this->connections = [$this->makeConnection(['protocol' => 'saml2']), $this->makeConnection(['tenant_id' => 'tenant-2', 'protocol' => 'saml2'])];
    }

    /**
     * Remove what the race used.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->tearDownRace();

        parent::tearDown();
    }

    /**
     * Racing runs delete each eligible row exactly once between them.
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
