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
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Races key rotations across processes on PostgreSQL and MySQL. No constraint
 * keeps a use to one `next` key, so the connection's lock does.
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
     * Skip without a shared database or pcntl; bind a fixed clock and fresh
     * freshness; create a SAML connection with a current signing key.
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

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => 'saml2']);

        self::assertSame(KeyState::CURRENT, $this->add()->key?->state);

        $this->outcomes = sys_get_temp_dir() . '/key-rotation-race-' . bin2hex(random_bytes(8));

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
     * Of processes racing to add the next signing key, exactly one adds it and
     * the rest conflict.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacingAdditionsAddsTheNextKey(): void
    {
        $outcomes = $this->race(fn (KeyService $keys): KeyResult => $keys->addNext(self::TENANT, $this->connection->id, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA));

        self::assertCount(1, array_keys($outcomes, KeyStatus::ADDED->value, true), implode(', ', $outcomes));
        self::assertCount(self::PROCESSES - 1, array_keys($outcomes, self::conflict(), true), implode(', ', $outcomes));
        self::assertSame(['current' => 1, 'next' => 1], $this->states());
    }

    /**
     * Racing additions inside transactions that read the keys first still add
     * only one, as the locked rechecks see past the snapshot.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacingAdditionsInsideACallersTransactionAddsTheNextKey(): void
    {
        $outcomes = $this->race(
            fn (KeyService $keys): KeyResult => $keys->addNext(self::TENANT, $this->connection->id, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA),
            true,
        );

        self::assertCount(1, array_keys($outcomes, KeyStatus::ADDED->value, true), implode(', ', $outcomes));
        self::assertCount(self::PROCESSES - 1, array_keys($outcomes, self::conflict(), true), implode(', ', $outcomes));
        self::assertSame(['current' => 1, 'next' => 1], $this->states());
    }

    /**
     * Of processes racing to promote the same next key, exactly one does,
     * leaving one current and one retiring key.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacingPromotionsMakesTheKeyCurrent(): void
    {
        $next = (string) $this->add()->key?->id;

        $outcomes = $this->race(fn (KeyService $keys): KeyResult => $keys->makeCurrent(self::TENANT, $this->connection->id, $next, Clients::browser()));

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
        return $this->keys()->addNext(self::TENANT, $this->connection->id, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA);
    }

    /**
     * Fork the processes, have each make the change at once on its own
     * connection, and collect their reports.
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
     * In a fork, prepare a connection and helpers, wait for the start, make the
     * change and report. A late process changes at once, which loosens the race
     * without breaking the assertions.
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
