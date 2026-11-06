<?php

declare(strict_types = 1);

namespace Tests\Integration\Domains;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Races runs of the domain recheck across processes, each with its own database
 * connection, on PostgreSQL and MySQL (BL-21, SSO-3.3, SSO-11.12): however they
 * interleave, every verified claim is checked by exactly one run, the rest
 * skipping it, so a suspension's times are written once and no claim is left
 * leased; and runs racing the removal of some of the claims never fail and
 * never write a claim that was removed. Each race runs with every process
 * working plainly, and again with each inside a transaction of its own that
 * read the domains before the race began, so a re-read that decides a write
 * must see what another process committed rather than its transaction's
 * snapshot (MySQL's `REPEATABLE READ`), and the locks must be taken in one
 * order for the races not to deadlock.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainRechecker::class)]
final class ConcurrentDomainRechecksTest extends TestCase
{
    use UsesConnections, UsesDomains;

    /** @var int Processes racing in each test. */
    private const int PROCESSES = 8;

    /** @var int Verified claims the processes race over; the first half answered absent, the rest found. */
    private const int CLAIMS = 10;

    /** @var list<int> The claims removed in a race with removals, one by each of the last four processes. */
    private const array REMOVED = [0, 1, 5, 6];

    /** @var string The token `makeDomain()` gives a claim. */
    private const string TOKEN = 'abababababababababababababababababababababababababababababababab';

    /** @var \Tests\Fixtures\FixedClock The clock every process reads. */
    private FixedClock $clock;

    /** @var list<\SineMacula\Laravel\Sso\Models\Connection> The two connections the claims alternate between, each of its own tenant. */
    private array $connections = [];

    /** @var list<\SineMacula\Laravel\Sso\Models\Domain> The claims, in the order they were made. */
    private array $claims = [];

    /** @var string Directory the processes report their results in. */
    private string $results;

    /**
     * Skip where processes cannot share the database, bind a fixed clock, a
     * fresh caller and a fake resolver, create the tables, and make the
     * verified claims, last checked a day ago, with their answers.
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

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');

        $dns = new FakeDnsResolver;

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(DnsResolver::class, $dns);

        $this->usePackageTables();

        $this->connections = [$this->makeConnection(['tenant_id' => 'tenant-0']), $this->makeConnection(['tenant_id' => 'tenant-1'])];

        for ($index = 0; $index < self::CLAIMS; $index++) {

            $this->claims[] = $this->makeDomain($this->connections[$index % 2], self::domainOf($index), [
                'state'                    => DomainState::VERIFIED,
                'last_successful_check_at' => CarbonImmutable::parse('2026-10-31T09:30:00Z')->addMinutes($index),
            ]);

            if ($index < self::CLAIMS / 2) {
                $dns->absent('_sso-verification.' . self::domainOf($index));

                continue;
            }

            $dns->found('_sso-verification.' . self::domainOf($index), self::TOKEN);
        }

        $this->clock->advance(3600);

        $this->results = sys_get_temp_dir() . '/domain-recheck-race-' . bin2hex(random_bytes(8));

        mkdir($this->results);
    }

    /**
     * Remove the results.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (glob(($this->results ?? sys_get_temp_dir() . '/none') . '/*') ?: [] as $file) {
            unlink($file);
        }

        if (isset($this->results) && is_dir($this->results)) {
            rmdir($this->results);
        }

        parent::tearDown();
    }

    /**
     * Runs racing over the same claims check each claim exactly once.
     *
     * @return void
     */
    public function testRacingRunsCheckEachClaimExactlyOnce(): void
    {
        $results = $this->race(static fn (DomainRechecker $rechecker): array => $rechecker->recheckAll(Clients::browser())->jsonSerialize()['entries']);

        $this->assertEachClaimCheckedOnce($results);
    }

    /**
     * The same race, each run inside a transaction of its own that read the
     * domains before the race began.
     *
     * @return void
     */
    public function testRacingRunsInsideACallersTransactionCheckEachClaimExactlyOnce(): void
    {
        $results = $this->race(static fn (DomainRechecker $rechecker): array => $rechecker->recheckAll(Clients::browser())->jsonSerialize()['entries'], true);

        $this->assertEachClaimCheckedOnce($results);
    }

    /**
     * Runs racing the removal of some of the claims never fail: each claim
     * removed is gone, checked at most once, and every other is checked exactly
     * once.
     *
     * @return void
     */
    public function testRacingRunsAndRemovalsNeverWriteARemovedClaim(): void
    {
        $this->assertRemovalsRaced($this->race($this->runOrRemove(...)));
    }

    /**
     * The same race, each process inside a transaction of its own that read the
     * domains before the race began.
     *
     * @return void
     */
    public function testRacingRunsAndRemovalsInsideACallersTransactionNeverWriteARemovedClaim(): void
    {
        $this->assertRemovalsRaced($this->race($this->runOrRemove(...), true));
    }

    /**
     * In a race with removals: the first four processes run the recheck, and
     * each of the last four removes one claim.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\DomainRechecker  $rechecker
     * @param  \SineMacula\Laravel\Sso\Domains\DomainService  $domains
     * @param  int  $process
     * @return list<array<string, ?string>>
     *
     * @throws \Throwable
     */
    private function runOrRemove(DomainRechecker $rechecker, DomainService $domains, int $process): array
    {
        if ($process < self::PROCESSES / 2) {
            return $rechecker->recheckAll(Clients::browser())->jsonSerialize()['entries'];
        }

        $index      = self::REMOVED[$process - self::PROCESSES / 2];
        $claim      = $this->claims[$index];
        $connection = $this->connections[$index % 2];
        $result     = $domains->remove($connection->tenant_id, $connection->id, $claim->domain, Clients::browser());

        return [['removed' => $claim->id, 'status' => $result->status->value]];
    }

    /**
     * Assert no process failed, every claim was checked by exactly one, its
     * times written once and as that check reported, and none is leased.
     *
     * @param  list<array{result: list<array<string, ?string>>, error: ?string}>  $results
     * @return void
     */
    private function assertEachClaimCheckedOnce(array $results): void
    {
        $checks = $this->checksOf($results);

        foreach ($this->claims as $index => $claim) {
            $this->assertCheckedOnce($index, $checks[$claim->id] ?? []);
        }

        self::assertSame(0, Domain::query()->whereNotNull('recheck_leased_until')->count());
    }

    /**
     * Assert no process failed, every removal removed its claim, which is gone
     * and was checked at most once, every other claim was checked exactly once,
     * and none is leased.
     *
     * @param  list<array{result: list<array<string, ?string>>, error: ?string}>  $results
     * @return void
     */
    private function assertRemovalsRaced(array $results): void
    {
        $checks  = $this->checksOf($results);
        $removed = self::removalsOf($results);

        foreach ($this->claims as $index => $claim) {

            if (!in_array($index, self::REMOVED, true)) {
                $this->assertCheckedOnce($index, $checks[$claim->id] ?? []);

                continue;
            }

            self::assertSame(DomainStatus::REMOVED->value, $removed[$claim->id] ?? null, "Claim {$index} was not removed.");
            self::assertLessThanOrEqual(1, count($checks[$claim->id] ?? []), "Claim {$index} was checked more than once.");
            self::assertFalse(Domain::query()->whereKey($claim->id)->exists(), "Claim {$index} was written after its removal.");
        }

        self::assertSame(self::CLAIMS - count(self::REMOVED), Domain::query()->count());
        self::assertSame(0, Domain::query()->whereNotNull('recheck_leased_until')->count());
    }

    /**
     * Assert the claim was checked by exactly one process, as its answer
     * should, and holds what that check wrote.
     *
     * @param  int  $index
     * @param  list<array<string, ?string>>  $checks
     * @return void
     */
    private function assertCheckedOnce(int $index, array $checks): void
    {
        $absent = $index < self::CLAIMS / 2;
        $row    = Domain::query()->findOrFail($this->claims[$index]->id);
        $now    = $this->clock->now()->toAtomString();

        self::assertCount(1, $checks, "Claim {$index} was not checked exactly once: " . json_encode($checks));
        self::assertSame($absent ? RecheckOutcome::SUSPENDED->value : RecheckOutcome::CONFIRMED->value, $checks[0]['outcome']);
        self::assertSame(DomainState::VERIFIED, $row->state);

        if (!$absent) {
            self::assertSame($now, $row->last_successful_check_at?->toAtomString());
            self::assertNull($row->linking_suspended_at);

            return;
        }

        self::assertSame($now, $row->linking_suspended_at?->toAtomString());
        self::assertSame($checks[0]['lapses_at'], $row->lapses_at?->utc()->format('Y-m-d\TH:i:s\Z'));
        self::assertSame('2026-11-04T10:30:00Z', $checks[0]['lapses_at']);
    }

    /**
     * The checks every process reported that did not skip, by claim, after
     * asserting no process failed.
     *
     * @param  list<array{result: list<array<string, ?string>>, error: ?string}>  $results
     * @return array<string, list<array<string, ?string>>>
     */
    private function checksOf(array $results): array
    {
        $checks = [];

        foreach ($results as $process => $result) {

            self::assertNull($result['error'], "Process {$process} failed: " . $result['error']);

            foreach ($result['result'] as $entry) {

                if (!self::isCheck($entry)) {
                    continue;
                }

                $checks[(string) $entry['domain_id']][] = $entry;
            }
        }

        return $checks;
    }

    /**
     * The status each removal answered, by the claim it removed.
     *
     * @param  list<array{result: list<array<string, ?string>>, error: ?string}>  $results
     * @return array<string, ?string>
     */
    private static function removalsOf(array $results): array
    {
        $removed = [];

        foreach ($results as $result) {
            foreach ($result['result'] as $entry) {

                if (!isset($entry['removed'])) {
                    continue;
                }

                $removed[$entry['removed']] = $entry['status'] ?? null;
            }
        }

        return $removed;
    }

    /**
     * Whether the entry a process reported is a check that did not skip.
     *
     * @param  array<string, ?string>  $entry
     * @return bool
     */
    private static function isCheck(array $entry): bool
    {
        return isset($entry['outcome']) && $entry['outcome'] !== RecheckOutcome::SKIPPED->value;
    }

    /**
     * Fork the processes, have each do its work at the same moment on a
     * connection of its own, and collect what each reported.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Domains\DomainRechecker, \SineMacula\Laravel\Sso\Domains\DomainService, int): list<array<string, ?string>>  $work
     * @param  bool  $inTransaction
     * @return list<array{result: list<array<string, ?string>>, error: ?string}>
     */
    private function race(\Closure $work, bool $inTransaction = false): array
    {
        DB::disconnect();

        $start = microtime(true) + 0.5;
        $pids  = [];

        for ($process = 0; $process < self::PROCESSES; $process++) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $start, $work, $inTransaction);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        $results = [];

        for ($process = 0; $process < self::PROCESSES; $process++) {

            /** @var array{result: list<array<string, ?string>>, error: ?string}|null $result */
            $result = json_decode((string) file_get_contents("{$this->results}/{$process}"), true);

            $results[] = $result ?? ['result' => [], 'error' => "process {$process} reported nothing"];
        }

        return $results;
    }

    /**
     * In a forked process: open a connection of its own and build the services,
     * so only the work itself runs after the start, wait for the start, do the
     * work, report what it did, and end without running the parent's shutdown.
     *
     * Racing inside a transaction, the process opens one and reads the domains
     * before the start, so the transaction's snapshot predates every change,
     * and commits after its own work.
     *
     * @param  int  $process
     * @param  float  $start
     * @param  \Closure(\SineMacula\Laravel\Sso\Domains\DomainRechecker, \SineMacula\Laravel\Sso\Domains\DomainService, int): list<array<string, ?string>>  $work
     * @param  bool  $inTransaction
     * @return never
     */
    private function runInChild(int $process, float $start, \Closure $work, bool $inTransaction): never
    {
        $report = ['result' => [], 'error' => null];

        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            /** @var \Illuminate\Foundation\Application $app */
            $app       = $this->app;
            $rechecker = $app->make(DomainRechecker::class);
            $domains   = $app->make(DomainService::class);
            $database  = DB::connection(StorageConnection::name());

            if ($inTransaction) {
                $database->beginTransaction();
                Domain::query()->get();
            }

            $wait = $start - microtime(true);

            if ($wait > 0) {
                usleep((int) ($wait * 1000000));
            }

            $report['result'] = $work($rechecker, $domains, $process);

            if ($inTransaction) {
                $database->commit();
            }
        } catch (\Throwable $e) {
            $report['error'] = $e::class . ': ' . $e->getMessage();
        }

        file_put_contents("{$this->results}/{$process}", json_encode($report));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * The domain of the claim at the index.
     *
     * @param  int  $index
     * @return string
     */
    private static function domainOf(int $index): string
    {
        return "d{$index}.example.com";
    }
}
