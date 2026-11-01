<?php

declare(strict_types = 1);

namespace Tests\Integration\SingleUse;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Races the default single-use store against itself across processes, each with
 * its own database connection, on PostgreSQL and MySQL: however the records of
 * one key interleave, exactly one is `recorded`, the rest are `seen`, none
 * fails, and the table holds the key once.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseSingleUseStore::class)]
final class ConcurrentSingleUseStoreTest extends TestCase
{
    /** @var int Processes racing in each test. */
    private const int PROCESSES = 12;

    /** @var string Absolute path to the shipped single-use keys migration. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The table's default name. */
    private const string TABLE = 'sso_single_use_keys';

    /** @var string The namespace every process records in. */
    private const string KEY_NAMESPACE = 'saml_assertion';

    /** @var string The key every process records. */
    private const string KEY = 'connection-1|https://idp.example.com|_assertion-id';

    /** @var \Tests\Fixtures\FixedClock The clock every process reads. */
    private FixedClock $clock;

    /** @var string Directory the processes report their outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, bind the fixed clock so
     * every process compares with the same now, create the shipped table, and
     * make the directory the processes report in.
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

        $this->clock = new FixedClock;

        $this->app?->instance(Clock::class, $this->clock);

        $this->migration()->up(); // @phpstan-ignore method.notFound

        $this->outcomes = sys_get_temp_dir() . '/single-use-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the outcomes and drop the shipped table.
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

        Schema::dropIfExists(self::TABLE);

        parent::tearDown();
    }

    /**
     * Processes racing to record a new key: exactly one records it.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacingRecordsOfANewKeyIsRecorded(): void
    {
        $outcomes = $this->race();

        self::assertCount(1, array_keys($outcomes, SingleUseOutcome::RECORDED->value, true), implode(', ', $outcomes));
        self::assertCount(self::PROCESSES - 1, array_keys($outcomes, SingleUseOutcome::SEEN->value, true), implode(', ', $outcomes));
        self::assertSame(['2026-10-31 12:01:00'], $this->expiriesHeld());
    }

    /**
     * Processes racing to record a key whose row has expired: exactly one
     * releases it and records the key again.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacingRecordsOfAnExpiredKeyIsRecorded(): void
    {
        DB::table(self::TABLE)->insert([
            'namespace'  => self::KEY_NAMESPACE,
            'key_digest' => hash('sha256', self::KEY),
            'expires_at' => '2026-10-31 11:59:00',
        ]);

        $outcomes = $this->race();

        self::assertCount(1, array_keys($outcomes, SingleUseOutcome::RECORDED->value, true), implode(', ', $outcomes));
        self::assertCount(self::PROCESSES - 1, array_keys($outcomes, SingleUseOutcome::SEEN->value, true), implode(', ', $outcomes));
        self::assertSame(['2026-10-31 12:01:00'], $this->expiriesHeld());
    }

    /**
     * Fork the processes, have each record the key at the same moment on a
     * connection of its own, and collect what each reported.
     *
     * @return list<string>
     */
    private function race(): array
    {
        DB::disconnect();

        $start = microtime(true) + 0.5;
        $pids  = [];

        for ($process = 0; $process < self::PROCESSES; $process++) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $start);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        $outcomes = [];

        for ($process = 0; $process < self::PROCESSES; $process++) {
            $outcomes[] = (string) file_get_contents("{$this->outcomes}/{$process}");
        }

        return $outcomes;
    }

    /**
     * In a forked process: open a connection of its own and build the store, so
     * only the record's own statements run after the start, wait for the start,
     * record the key, report the outcome, and end without running the parent's
     * shutdown.
     *
     * A process that reaches the start late, on a loaded machine, records at
     * once rather than failing: the race is then less close, but every
     * assertion still holds.
     *
     * @param  int  $process
     * @param  float  $start
     * @return never
     */
    private function runInChild(int $process, float $start): never
    {
        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            $store = new DatabaseSingleUseStore($this->clock);
            $wait  = $start - microtime(true);

            if ($wait > 0) {
                usleep((int) ($wait * 1000000));
            }

            $outcome = $store->record(self::KEY_NAMESPACE, self::KEY, $this->clock->now()->addMinute())->value;
        } catch (\Throwable $e) {
            $outcome = 'error: ' . $e->getMessage();
        }

        file_put_contents("{$this->outcomes}/{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * The expiry of every row the table holds for the key.
     *
     * @return list<mixed>
     */
    private function expiriesHeld(): array
    {
        return array_values(DB::table(self::TABLE)
            ->where('namespace', self::KEY_NAMESPACE)
            ->where('key_digest', hash('sha256', self::KEY))
            ->pluck('expires_at')
            ->all());
    }

    /**
     * Require the shipped anonymous-class migration and return it.
     *
     * @return \Illuminate\Database\Migrations\Migration
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function migration(): Migration
    {
        $migration = include self::MIGRATION_PATH;

        if (!$migration instanceof Migration) {
            self::fail('The single-use keys migration did not return a Migration instance.');
        }

        return $migration;
    }
}
