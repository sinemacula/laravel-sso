<?php

declare(strict_types = 1);

namespace Tests\Integration\Keys;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyStatus;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyResult;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Races a connection's key rotations against each other across processes, each
 * with its own database connection, on PostgreSQL and MySQL (BL-12, SSO-2.7).
 * Each change reads the connection again locked for update, which serialises
 * its rotations: however the calls interleave, exactly one adds the `next` key
 * of a use, or makes it current, and the rest are `key_state_conflict`. No
 * database constraint keeps a use to one `next` key, so the lock is what does.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyService::class)]
#[CoversClass(ConnectionFinder::class)]
final class ConcurrentKeyRotationTest extends TestCase
{
    use UsesConnections;

    /** @var int Processes racing in each test. */
    private const int PROCESSES = 8;

    /** @var string The tenant whose connection the processes rotate. */
    private const string TENANT = 'tenant-1';

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the processes rotate. */
    private Connection $connection;

    /** @var string Directory the processes report their outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, bind a fixed clock and a
     * freshness contract that answers `fresh`, create the tables and a SAML
     * connection with a current signing key, and make the directory the
     * processes report in.
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

        $this->createConnectionTables();

        $this->connection = $this->makeConnection(['protocol' => 'saml2']);

        self::assertSame(KeyState::CURRENT, $this->add()->key?->state);

        $this->outcomes = sys_get_temp_dir() . '/key-rotation-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the outcomes and drop the tables.
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

        if (isset($this->connection)) {
            $this->dropConnectionTables();
        }

        parent::tearDown();
    }

    /**
     * Processes racing to add the next signing key: exactly one adds it, the
     * rest are a conflict, and the use holds one `next` key.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacingAdditionsAddsTheNextKey(): void
    {
        $outcomes = $this->race(fn (KeyService $keys): KeyResult => $keys->addNext(self::TENANT, $this->connection->id, KeyUse::SP_SIGNING, KeyType::EC));

        self::assertCount(1, array_keys($outcomes, KeyStatus::ADDED->value, true), implode(', ', $outcomes));
        self::assertCount(self::PROCESSES - 1, array_keys($outcomes, self::conflict(), true), implode(', ', $outcomes));
        self::assertSame(['current' => 1, 'next' => 1], $this->states());
    }

    /**
     * Processes racing to add the next signing key, each inside a transaction
     * of its own that read the keys before the race began: only one adds it.
     *
     * The rechecks under the connection's lock read the keys locked, so they
     * see the key another process added since, not the snapshot the caller's
     * transaction took (MySQL's `REPEATABLE READ`).
     *
     * @return void
     */
    public function testExactlyOneOfTheRacingAdditionsInsideACallersTransactionAddsTheNextKey(): void
    {
        $outcomes = $this->race(fn (KeyService $keys): KeyResult => $keys->addNext(self::TENANT, $this->connection->id, KeyUse::SP_SIGNING, KeyType::EC), true);

        self::assertCount(1, array_keys($outcomes, KeyStatus::ADDED->value, true), implode(', ', $outcomes));
        self::assertCount(self::PROCESSES - 1, array_keys($outcomes, self::conflict(), true), implode(', ', $outcomes));
        self::assertSame(['current' => 1, 'next' => 1], $this->states());
    }

    /**
     * Processes racing to make the same next key current: exactly one does, the
     * rest are a conflict, and the use holds one current key and one retiring
     * key.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacingPromotionsMakesTheKeyCurrent(): void
    {
        $next = (string) $this->add()->key?->id;

        $outcomes = $this->race(fn (KeyService $keys): KeyResult => $keys->makeCurrent(self::TENANT, $this->connection->id, $next));

        self::assertCount(1, array_keys($outcomes, KeyStatus::MADE_CURRENT->value, true), implode(', ', $outcomes));
        self::assertCount(self::PROCESSES - 1, array_keys($outcomes, self::conflict(), true), implode(', ', $outcomes));
        self::assertSame(['current' => 1, 'retiring' => 1], $this->states());
        self::assertSame('current', ConnectionKey::query()->findOrFail($next)->getRawOriginal('state'));
    }

    /**
     * Add a P-256 signing key to the connection.
     *
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     */
    private function add(): KeyResult
    {
        return $this->keys()->addNext(self::TENANT, $this->connection->id, KeyUse::SP_SIGNING, KeyType::EC);
    }

    /**
     * Fork the processes, have each make the change at the same moment on a
     * connection of its own, and collect what each reported.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Keys\KeyService): \SineMacula\Laravel\Sso\Keys\KeyResult  $change
     * @param  bool  $inTransaction
     * @return list<string>
     */
    private function race(\Closure $change, bool $inTransaction = false): array
    {
        DB::disconnect();

        $start = microtime(true) + 0.5;
        $pids  = [];

        for ($process = 0; $process < self::PROCESSES; $process++) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $start, $change, $inTransaction);
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
     * In a forked process: open a connection of its own and build the helpers,
     * so only the change's own work runs after the start, wait for the start,
     * make the change, report the outcome, and end without running the parent's
     * shutdown.
     *
     * Racing inside a transaction, the process opens one and reads the keys
     * before the start, so the transaction's snapshot predates every change,
     * and commits after its own.
     *
     * A process that reaches the start late, on a loaded machine, changes at
     * once rather than failing: the race is then less close, but every
     * assertion still holds.
     *
     * @param  int  $process
     * @param  float  $start
     * @param  \Closure(\SineMacula\Laravel\Sso\Keys\KeyService): \SineMacula\Laravel\Sso\Keys\KeyResult  $change
     * @param  bool  $inTransaction
     * @return never
     */
    private function runInChild(int $process, float $start, \Closure $change, bool $inTransaction): never
    {
        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            $keys     = $this->keys();
            $database = DB::connection(StorageConnection::name());

            if ($inTransaction) {
                $database->beginTransaction();
                $this->states();
            }

            $wait = $start - microtime(true);

            if ($wait > 0) {
                usleep((int) ($wait * 1000000));
            }

            $result = $change($keys);

            if ($inTransaction) {
                $database->commit();
            }

            $outcome = $result->reason === null ? $result->status->value : $result->status->value . ':' . $result->reason->value;
        } catch (\Throwable $e) {
            $outcome = 'error: ' . $e->getMessage();
        }

        file_put_contents("{$this->outcomes}/{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * How many of the connection's signing keys are in each state.
     *
     * @return array<string, int>
     */
    private function states(): array
    {
        $states = array_count_values(array_map(
            static fn (mixed $state): string => is_string($state) ? $state : 'none',
            ConnectionKey::query()->where('connection_id', $this->connection->id)->where('use', KeyUse::SP_SIGNING->value)->toBase()->pluck('state')->all(),
        ));

        ksort($states);

        return $states;
    }

    /**
     * The key helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Keys\KeyService
     */
    private function keys(): KeyService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(KeyService::class);
    }

    /**
     * The outcome a process reports for a change refused as a conflict.
     *
     * @return string
     */
    private static function conflict(): string
    {
        return KeyStatus::REFUSED->value . ':' . FailureReason::KEY_STATE_CONFLICT->value;
    }
}
