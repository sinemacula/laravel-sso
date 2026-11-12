<?php

declare(strict_types = 1);

namespace Tests\Integration\Flows;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Protocols\StartingDriver;
use Tests\TestCase;

/**
 * Races a start against a trust change between its read and its insert, in
 * process and across processes. Skipped across processes on SQLite and without
 * `pcntl`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequestService::class)]
final class StartTrustChangeRaceTest extends TestCase
{
    use UsesConnections;

    /** @var float Seconds a racer waits for the other's signal before it gives up. */
    private const float SIGNAL_SECONDS = 10.0;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection started through. */
    private Connection $connection;

    /** @var \Tests\Fixtures\Protocols\StartingDriver The driver the connection runs over. */
    private StartingDriver $driver;

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /**
     * Bind a fixed clock and an open limiter, register the application and
     * driver, and seed a usable connection.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(AttemptLimiter::class, new readonly class implements AttemptLimiter {
            /**
             * Allow every attempt.
             *
             * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject  $subject
             * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptResult
             */
            #[\Override]
            public function attempt(AttemptSubject $subject): AttemptResult
            {
                unset($subject);

                return AttemptResult::allowed();
            }
        });

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $this->driver = new StartingDriver;
        $driver       = $this->driver;

        app(ProtocolManager::class)->extend(StartingDriver::NAME, fn (): StartingDriver => $driver);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => StartingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => 'https://idp.example.com']]);
        $this->outcomes   = sys_get_temp_dir() . '/start-trust-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove this test's signals and outcomes.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if (isset($this->outcomes) && is_dir($this->outcomes)) {

            foreach (glob($this->outcomes . '/*') ?: [] as $file) {
                @unlink($file);
            }

            @rmdir($this->outcomes);
        }

        parent::tearDown();
    }

    /**
     * A trust change while the driver started refuses the start under the lock,
     * storing nothing.
     *
     * @return void
     */
    public function testATrustChangeWhileTheDriverStartedRefusesTheStart(): void
    {
        $this->driver->onStart = function (): void {
            self::assertTrue($this->hasChangedTrust());
        };

        $result = $this->start();

        self::assertSame([true, FailureReason::CONNECTION_UNAVAILABLE], [$result->isRefused(), $result->reason]);
        self::assertSame(0, AuthorizationRequest::query()->count());
        self::assertSame(1, $this->connection->fresh()?->trust_version);
    }

    /**
     * Rows of `[in transaction]`: the change made plainly, or in a transaction
     * that read first.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideChanges(): iterable
    {
        yield from [
            'plainly'              => [false],
            'inside a transaction' => [true],
        ];
    }

    /**
     * Across processes, a trust change while the start is held refuses it,
     * storing nothing.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideChanges')]
    public function testATrustChangeInAnotherProcessRefusesTheStart(bool $inTransaction): void
    {
        if (DB::connection()->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        $started = "{$this->outcomes}/started";
        $changed = "{$this->outcomes}/changed";

        $outcomes = $this->race([
            [function () use ($started, $changed): string {
                $this->driver->onStart = static function () use ($started, $changed): void {
                    touch($started);
                    self::await($changed);
                };

                $result = $this->start();

                return $result->status->value . ':' . ($result->reason->value ?? '-');
            }, false],
            [function () use ($started, $changed): string {
                if (!self::isSignalled($started)) {
                    return 'error: the start never signalled its driver started';
                }

                try {
                    return $this->hasChangedTrust() ? 'changed' : 'unchanged';
                } finally {
                    touch($changed);
                }
            }, $inTransaction],
        ]);

        self::assertSame(['refused:connection_unavailable', 'changed'], $outcomes);
        self::assertSame(0, AuthorizationRequest::query()->count());
        self::assertSame(1, $this->connection->fresh()?->trust_version);
    }

    /**
     * Start a `sign_in` for `web` through the connection.
     *
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    private function start(): StartResult
    {
        return app(AuthorizationRequestService::class)->start('web', Purpose::SIGN_IN, $this->connection->id, Clients::browser());
    }

    /**
     * Void what is in flight and raise the trust version under the lock;
     * whether the connection was there.
     *
     * @return bool
     */
    private function hasChangedTrust(): bool
    {
        return DB::connection(StorageConnection::name())->transaction(function (): bool {
            $locked = Connection::query()->useWritePdo()->lockForUpdate()->whereKey($this->connection->id)->first();

            if ($locked === null) {
                return false;
            }

            app(InFlightVoider::class)->voidFor($locked);

            return true;
        });
    }

    /**
     * Fork a process per racer, plain or in a transaction, and collect what
     * each reported, in order.
     *
     * @param  list<array{0: \Closure(): string, 1: bool}>  $racers
     * @return list<string>
     */
    private function race(array $racers): array
    {
        DB::disconnect();

        $pids = [];

        foreach ($racers as $process => [$work, $inTransaction]) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $work, $inTransaction);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        $outcomes = [];

        foreach (array_keys($racers) as $process) {
            $outcomes[] = (string) file_get_contents("{$this->outcomes}/{$process}");
        }

        return $outcomes;
    }

    /**
     * In a child: run the work and report; in a transaction, read under
     * `REPEATABLE READ` first.
     *
     * @param  int  $process
     * @param  \Closure(): string  $work
     * @param  bool  $inTransaction
     * @return never
     */
    private function runInChild(int $process, \Closure $work, bool $inTransaction): never
    {
        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            $database = DB::connection(StorageConnection::name());

            if ($inTransaction) {
                $database->statement(self::repeatableReadStatement($database->getDriverName()));
                $database->beginTransaction();
                Connection::query()->whereKey($this->connection->id)->get();
            }

            $outcome = $work();

            if ($inTransaction) {
                $database->commit();
            }
        } catch (\Throwable $e) {
            $outcome = 'error: ' . $e::class . ': ' . $e->getMessage();
        }

        file_put_contents("{$this->outcomes}/{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Wait for the signal file up to `SIGNAL_SECONDS`, failing loudly so a
     * serial run never passes as a race.
     *
     * @param  string  $signal
     * @return void
     *
     * @throws \RuntimeException
     */
    private static function await(string $signal): void
    {
        if (!self::isSignalled($signal)) {
            throw new \RuntimeException(sprintf('The barrier timed out waiting for [%s].', basename($signal)));
        }
    }

    /**
     * Wait for the signal file up to `SIGNAL_SECONDS`; whether it appeared.
     *
     * @param  string  $signal
     * @return bool
     */
    private static function isSignalled(string $signal): bool
    {
        $deadline = microtime(true) + self::SIGNAL_SECONDS;

        while (!file_exists($signal)) {

            if (microtime(true) > $deadline) {
                return false;
            }

            usleep(1000);
            clearstatcache(true, $signal);
        }

        return true;
    }

    /**
     * The statement that makes every later transaction of the session
     * `REPEATABLE READ`.
     *
     * @param  string  $driver
     * @return string
     *
     * @throws \LogicException
     */
    private static function repeatableReadStatement(string $driver): string
    {
        return match ($driver) {
            'pgsql' => 'set session characteristics as transaction isolation level repeatable read',
            'mysql' => 'set session transaction isolation level repeatable read',
            default => throw new \LogicException(sprintf('No statement sets the isolation on [%s].', $driver)),
        };
    }
}
