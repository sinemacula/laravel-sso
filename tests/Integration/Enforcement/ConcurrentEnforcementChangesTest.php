<?php

declare(strict_types = 1);

namespace Tests\Integration\Enforcement;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\EnforcementFinder;
use SineMacula\Laravel\Sso\Enforcement\EnforcementResult;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Races changes to one tenant's enforcement across processes, each with its own
 * database connection, on PostgreSQL and MySQL (SSO-4.3, SSO-4.5, SSO-4.6).
 * Each change locks the tenant's row, then the connections it names in id
 * order, and judges itself again on what the locks show: racing first changes
 * store one row and one change, racing changes are serialised into one chain of
 * versions, and a change waits for a connection another process is disabling
 * and then sees it disabled.
 *
 * Each race runs twice: plainly, and with every process inside a transaction of
 * its own that read the enforcement table before the race began, so a locking
 * read that answered from that snapshot (MySQL's `REPEATABLE READ`) would fail
 * it.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnforcementService::class)]
#[CoversClass(EnforcementFinder::class)]
final class ConcurrentEnforcementChangesTest extends TestCase
{
    use UsesConnections;

    /** @var int Processes racing in each test. */
    private const int PROCESSES = 8;

    /** @var string The tenant whose enforcement the processes change. */
    private const string TENANT = 'tenant-1';

    /** @var float How long, in seconds, a process waits for the other before it gives up. */
    private const float DEADLINE_SECONDS = 30.0;

    /** @var list<\SineMacula\Laravel\Sso\Models\Connection> The tenant's connections, each enabled with a completed sign-in. */
    private array $connections = [];

    /** @var string Directory the processes report their outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, bind a fixed clock and a
     * fresh caller, switch the feature on, create the tables and a connection
     * per process, and make the directory the processes report in.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        Config::set('sso.features.enforcement', true);

        $this->usePackageTables();

        for ($process = 0; $process < self::PROCESSES; $process++) {
            $this->connections[] = $this->makeConnection(['enabled' => true, 'has_completed_sign_in' => true]);
        }

        $this->outcomes = sys_get_temp_dir() . '/enforcement-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the outcomes.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (glob(($this->outcomes ?? sys_get_temp_dir() . '/none') . '/*') ?: [] as $file) {
            unlink($file);
        }

        if (isset($this->outcomes) && is_dir($this->outcomes)) {
            rmdir($this->outcomes);
        }

        parent::tearDown();
    }

    /**
     * Rows of `[inTransaction]`: each race plainly, and with every process
     * inside a transaction of its own.
     *
     * @return iterable<string, array{bool}>
     */
    public static function provideModes(): iterable
    {
        yield 'plainly' => [false];
        yield 'inside a caller\'s transaction' => [true];
    }

    /**
     * Processes racing to make the tenant's first change, each the same: one
     * stores it, the rest find it stored and are unchanged, and the tenant has
     * one row.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testExactlyOneOfTheRacingFirstChangesStoresTheRule(bool $inTransaction): void
    {
        $id       = $this->connections[0]->id;
        $outcomes = $this->race(array_fill(0, self::PROCESSES, [$id]), $inTransaction);
        $statuses = array_column($outcomes, 'status');

        self::assertCount(1, array_keys($statuses, 'updated', true), (string) json_encode($outcomes));
        self::assertCount(self::PROCESSES - 1, array_keys($statuses, 'unchanged', true), (string) json_encode($outcomes));

        $stored = TenantEnforcement::query()->sole();

        self::assertTrue($stored->enabled);
        self::assertSame([$id], $stored->connection_ids);
        self::assertSame(array_values(array_unique(array_column($outcomes, 'version'))), [$stored->version]);
    }

    /**
     * Processes racing to change the rule, each to a set of its own: every
     * change is made, each against the one committed before it, so the versions
     * are distinct and form one chain, and the row holds the last.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testRacingChangesAreSerialized(bool $inTransaction): void
    {
        $initial = $this->service()->update(self::TENANT, false, [$this->connections[0]->id], Clients::browser());

        self::assertTrue($initial->isChanged());

        $sets     = array_map(static fn (Connection $connection): array => [$connection->id], $this->connections);
        $outcomes = $this->race($sets, $inTransaction);

        self::assertSame(array_fill(0, self::PROCESSES, 'updated'), array_column($outcomes, 'status'), (string) json_encode($outcomes));

        $versions = array_column($outcomes, 'version');

        self::assertCount(self::PROCESSES, array_unique($versions));
        self::assertNotContains($initial->enforcement?->version, $versions);

        $last   = $this->chainFrom((string) $initial->enforcement?->version, $outcomes);
        $stored = TenantEnforcement::query()->sole();

        self::assertTrue($stored->enabled);
        self::assertSame($outcomes[$last]['version'], $stored->version);
        self::assertSame($sets[$last], $stored->connection_ids);
    }

    /**
     * A change that turns enforcement on, with as its only completed connection
     * one another process holds locked while it disables it, waits for that
     * process to commit and is then refused.
     *
     * The disabling process commits only once the database shows a session
     * waiting on its lock, however late the change starts. The change runs its
     * plain check before it takes any lock, so a change seen waiting saw the
     * connection still enabled there: its refusal can only come from the locked
     * read again. It stores no rule: the row it locked stays unconfigured.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testAChangeWaitsForAConnectionBeingDisabled(bool $inTransaction): void
    {
        $connection = $this->connections[0];
        $locked     = "{$this->outcomes}/locked";

        $outcomes = $this->inProcesses([
            fn (): array => $this->disableOnceAChangeWaits($connection, $locked),
            fn (): array => $this->turnOnOnceLocked($connection, $locked, $inTransaction),
        ]);

        $reported = (string) json_encode($outcomes);

        self::assertSame('committed', $outcomes[0]['status'] ?? null, $reported);
        self::assertTrue($outcomes[0]['sawWaiter'] ?? false, 'No change waited on the lock: ' . $reported);
        self::assertSame('refused', $outcomes[1]['status'] ?? null, $reported);
        self::assertSame('completed_sign_in_required', $outcomes[1]['reason'] ?? null, $reported);
        self::assertNull((new EnforcementFinder)->find(self::TENANT), $reported);
        self::assertNull(TenantEnforcement::query()->sole()->version, $reported);
        self::assertFalse(Connection::query()->findOrFail($connection->id)->enabled);
    }

    /**
     * Follow the chain of versions from the one given, each change replacing
     * the one before it, and answer which process made the last.
     *
     * @param  string  $initial
     * @param  list<array<string, mixed>>  $outcomes
     * @return int
     */
    private function chainFrom(string $initial, array $outcomes): int
    {
        $byPrevious = [];

        foreach ($outcomes as $process => $outcome) {

            $previous = $outcome['previous'] ?? null;

            self::assertIsString($previous, 'A change replaced no version.');
            self::assertArrayNotHasKey($previous, $byPrevious, 'Two changes replaced the same version.');

            $byPrevious[$previous] = $process;
        }

        $version = $initial;
        $last    = -1;

        for ($step = 0; $step < self::PROCESSES; $step++) {

            self::assertArrayHasKey($version, $byPrevious, 'The changes do not form one chain.');

            $last    = $byPrevious[$version];
            $version = $outcomes[$last]['version'] ?? null;

            self::assertIsString($version, 'A change stored no version.');
        }

        return $last;
    }

    /**
     * Fork a process per set of ids, have each turn the tenant's enforcement on
     * with its set at the same moment on a connection of its own, and collect
     * what each reported.
     *
     * @param  list<list<string>>  $sets
     * @param  bool  $inTransaction
     * @return list<array<string, mixed>>
     */
    private function race(array $sets, bool $inTransaction): array
    {
        $start = microtime(true) + 0.5;

        return $this->inProcesses(array_map(
            fn (array $ids): \Closure => fn (): array => $this->racer($start, $ids, $inTransaction),
            $sets,
        ));
    }

    /**
     * In a forked process: build the helper and listen for the change, open a
     * transaction that reads the enforcement table first when asked, wait for
     * the start, make the change, commit, and report the outcome, the version
     * and the version the change replaced.
     *
     * A process that reaches the start late, on a loaded machine, changes at
     * once rather than failing: the race is then less close, but every
     * assertion still holds.
     *
     * @param  float  $start
     * @param  list<string>  $ids
     * @param  bool  $inTransaction
     * @return array<string, mixed>
     */
    private function racer(float $start, array $ids, bool $inTransaction): array
    {
        $service  = $this->service();
        $database = DB::connection(StorageConnection::name());
        /** @var \ArrayObject<int, ?string> $reported */
        $reported = new \ArrayObject;

        Event::listen(EnforcementChanged::class, static function (EnforcementChanged $event) use ($reported): void {
            $reported->append($event->previousVersion);
        });

        if ($inTransaction) {
            $database->beginTransaction();
            TenantEnforcement::query()->count();
        }

        $wait = $start - microtime(true);

        if ($wait > 0) {
            usleep((int) ($wait * 1000000));
        }

        $result = $service->update(self::TENANT, true, $ids, Clients::browser());

        if ($inTransaction) {
            $database->commit();
        }

        return [...self::outcomeOf($result), 'previous' => $reported[0] ?? null];
    }

    /**
     * In a forked process: lock the connection, disable it, say so, hold the
     * lock until the database shows a session waiting on it (or the deadline
     * passes), and commit, reporting whether one waited.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $locked
     * @return array<string, mixed>
     */
    private function disableOnceAChangeWaits(Connection $connection, string $locked): array
    {
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        Connection::query()->whereKey($connection->id)->lockForUpdate()->firstOrFail()->forceFill(['enabled' => false])->save();

        touch($locked);

        $sawWaiter = self::hasAWaiterBeforeTheDeadline($database);

        $database->commit();

        return ['status' => 'committed', 'sawWaiter' => $sawWaiter];
    }

    /**
     * Poll, on the connection that holds the lock, until another session waits
     * on a lock it holds, or the deadline passes; answer whether one did.
     *
     * @param  \Illuminate\Database\Connection  $database
     * @return bool
     *
     * @throws \LogicException
     */
    private static function hasAWaiterBeforeTheDeadline(\Illuminate\Database\Connection $database): bool
    {
        $query    = self::waitersQuery($database->getDriverName());
        $deadline = microtime(true) + self::DEADLINE_SECONDS;

        do {

            $row = $database->selectOne($query, [], false);

            if ($row instanceof \stdClass && (int) ($row->waiting ?? 0) > 0) {
                return true;
            }

            usleep(10000);
        } while (microtime(true) < $deadline);

        return false;
    }

    /**
     * The query that counts the sessions waiting on a lock the current session
     * holds.
     *
     * @param  string  $driver
     * @return string
     *
     * @throws \LogicException
     */
    private static function waitersQuery(string $driver): string
    {
        return match ($driver) {
            'pgsql' => 'select count(*) as waiting from (select distinct pid from pg_locks where not granted) as waits where pg_backend_pid() = any(pg_blocking_pids(waits.pid))',
            'mysql' => 'select count(*) as waiting from performance_schema.data_lock_waits where BLOCKING_THREAD_ID = ps_current_thread_id()',
            default => throw new \LogicException(sprintf('No query finds the sessions waiting on a lock on [%s].', $driver)),
        };
    }

    /**
     * In a forked process: open a transaction that reads the enforcement table
     * first when asked, wait until the connection is locked, turn enforcement
     * on with it, commit, and report the outcome and, for diagnosis only, how
     * long the change took.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $locked
     * @param  bool  $inTransaction
     * @return array<string, mixed>
     */
    private function turnOnOnceLocked(Connection $connection, string $locked, bool $inTransaction): array
    {
        $service  = $this->service();
        $database = DB::connection(StorageConnection::name());

        if ($inTransaction) {
            $database->beginTransaction();
            TenantEnforcement::query()->count();
        }

        $deadline = microtime(true) + self::DEADLINE_SECONDS;

        while (!file_exists($locked) && microtime(true) < $deadline) {
            usleep(5000);
        }

        $began  = microtime(true);
        $result = $service->update(self::TENANT, true, [$connection->id], Clients::browser());
        $waited = microtime(true) - $began;

        if ($inTransaction) {
            $database->commit();
        }

        return [...self::outcomeOf($result), 'waited' => $waited];
    }

    /**
     * Fork a process per body, have each run its body on a connection of its
     * own, and collect what each reported, in order.
     *
     * @param  list<\Closure(): array<string, mixed>>  $bodies
     * @return list<array<string, mixed>>
     */
    private function inProcesses(array $bodies): array
    {
        DB::disconnect();

        $pids = [];

        foreach ($bodies as $process => $body) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $body);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        $outcomes = [];

        foreach (array_keys($bodies) as $process) {

            $outcome = json_decode((string) file_get_contents("{$this->outcomes}/{$process}"), true);

            $outcomes[] = is_array($outcome) ? $outcome : ['status' => 'unreadable'];
        }

        return $outcomes;
    }

    /**
     * In a forked process: open a connection of its own, run the body, report
     * what it answered, or the error it threw, and end without running the
     * parent's shutdown.
     *
     * @param  int  $process
     * @param  \Closure(): array<string, mixed>  $body
     * @return never
     */
    private function runInChild(int $process, \Closure $body): never
    {
        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            $outcome = $body();
        } catch (\Throwable $e) {
            $outcome = ['status' => 'error', 'reason' => $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/{$process}", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * The enforcement helper, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementService
     */
    private function service(): EnforcementService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(EnforcementService::class);
    }

    /**
     * The status, reason and version of a result, as a process reports them.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementResult  $result
     * @return array{status: string, reason: ?string, version: ?string}
     */
    private static function outcomeOf(EnforcementResult $result): array
    {
        return ['status' => $result->status->value, 'reason' => $result->reason?->value, 'version' => $result->enforcement?->version];
    }
}
