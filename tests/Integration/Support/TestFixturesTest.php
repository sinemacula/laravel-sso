<?php

declare(strict_types = 1);

namespace Tests\Integration\Support;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\QueryException;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\Verifier;
use SineMacula\Laravel\Sso\Handoffs\HandoffCode;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\SsoModel;
use SineMacula\Laravel\Sso\Secrets\Secret;
use Tests\Concerns\FailsDatabaseStatements;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\RunsLongLivedApplication;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesUnreliableCache;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Queue\RecordsItsRun;
use Tests\TestCase;

/**
 * Tests that the operational test fixtures do what they say.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class TestFixturesTest extends TestCase
{
    use FailsDatabaseStatements, InteractsWithLaggingReplica, RunsLongLivedApplication, UsesConnections, UsesUnreliableCache;

    /** @var bool Whether the running test needs the replica. */
    private bool $lagging = false;

    /**
     * Bind a fixed clock and create the tables the running test needs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock);

        if (str_contains($this->name(), 'Replica')) {
            $this->lagging = true;

            $this->migrateSsoTablesOnPrimaryAndReplica();

            return;
        }

        $this->usePackageTables();
    }

    /**
     * Remove what the running test made.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->lagging) {
            $this->removeLaggingReplicaFiles();
        }

        parent::tearDown();
    }

    /**
     * A row written through the split connection is on the primary alone.
     *
     * @return void
     */
    public function testTheReplicaLagsBehindThePrimary(): void
    {
        $connection = $this->makeConnection();

        self::assertNull(Connection::query()->find($connection->id));
        self::assertNotNull(Connection::query()->useWritePdo()->find($connection->id));
    }

    /**
     * A replica copy goes stale both ways when the primary moves on.
     *
     * @return void
     */
    public function testACopyOnTheReplicaGoesStale(): void
    {
        $connection = $this->makeConnection(['enabled' => true]);

        $this->copyRowToReplica(StorageConnection::table('connections.table'), $connection->id);

        Connection::query()->useWritePdo()->whereKey($connection->id)->update(['enabled' => false]);

        self::assertTrue(Connection::query()->findOrFail($connection->id)->enabled);
        self::assertFalse(Connection::query()->useWritePdo()->findOrFail($connection->id)->enabled);

        $this->deleteRowFromReplica(StorageConnection::table('connections.table'), $connection->id);

        self::assertNull(Connection::query()->find($connection->id));
    }

    /**
     * An armed statement fails once at its occurrence.
     *
     * @return void
     */
    public function testAnArmedStatementFailsAtItsOccurrence(): void
    {
        $this->failStatement(self::onTable('select', 'sso_connections'), 2);

        self::assertSame(0, Connection::query()->count());

        $failure = self::thrownBy(static fn (): int => Connection::query()->count());

        self::assertInstanceOf(QueryException::class, $failure);
        self::assertTrue(self::isInjectedFailure($failure));

        self::assertSame(0, Connection::query()->count());
        self::assertSame(1, $this->databaseFailuresFired());
    }

    /**
     * A failed commit throws and rolls the transaction back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedCommitRollsBack(): void
    {
        $this->failCommit();

        $database = DB::connection(StorageConnection::name());

        try {
            $database->transaction(function (): void {
                $this->makeConnection();
            });
            self::fail('The commit did not fail.');
        } catch (QueryException $exception) {
            self::assertTrue(self::isInjectedFailure($exception));
        }

        self::assertSame(0, Connection::query()->count());
        self::assertSame(0, $database->transactionLevel());

        $this->makeConnection();

        self::assertSame(1, Connection::query()->count());
    }

    /**
     * A broken cache throws on every call, and counts them.
     *
     * @return void
     */
    public function testABrokenCacheThrows(): void
    {
        $store = $this->breakTheCache();

        foreach ([static fn (): mixed => Cache::get('a'), static fn (): mixed => Cache::put('a', 1, 60), static fn (): mixed => Cache::lock('a', 60)] as $call) {
            try {
                $call();
                self::fail('The broken cache answered.');
            } catch (\RuntimeException $exception) {
                self::assertSame('The cache is down.', $exception->getMessage());
            }
        }

        self::assertSame(3, $store->calls);
    }

    /**
     * A lying cache loses writes and answers what it was told to.
     *
     * @return void
     */
    public function testALyingCacheLies(): void
    {
        $this->makeTheCacheLie('a lie', false);

        self::assertTrue(Cache::put('a', 'the truth', 60));
        self::assertSame('a lie', Cache::get('a'));
        self::assertFalse(Cache::lock('a', 60)->get());

        $this->makeTheCacheLie(null, true);

        self::assertTrue(Cache::put('a', 'the truth', 60));
        self::assertNull(Cache::get('a'));
        self::assertTrue(Cache::lock('a', 60)->get());
    }

    /**
     * Each request runs in a fresh sandbox of one root application.
     *
     * @return void
     */
    public function testOneWorkerKeepsOneApplicationAcrossRequests(): void
    {
        $root = $this->app;
        $made = 0;

        $this->app?->scoped(RecordsItsRun::SCOPED, static function () use (&$made): object {
            $made++;

            return new \stdClass;
        });

        Route::get('/instance', static function (): JsonResponse {

            $clean = !app()->bound('sso.test.marker');

            app()->instance('sso.test.marker', true);

            return new JsonResponse(['same' => app(RecordsItsRun::SCOPED) === app(RecordsItsRun::SCOPED), 'clean' => $clean]);
        });
        Route::get('/throw', static function (): never {
            throw new \RuntimeException('boom');
        });

        $this->bootLongLivedWorker();

        $first = $this->serve(self::workerRequest('GET', '/instance'))->assertOk()->json();

        $this->serve(self::workerRequest('GET', '/throw'))->assertStatus(500);

        $second = $this->serve(self::workerRequest('GET', '/instance'))->assertOk()->json();

        self::assertSame(['same' => true, 'clean' => true], $first);
        self::assertSame(['same' => true, 'clean' => true], $second);
        self::assertSame(2, $made);
        self::assertFalse($root?->bound('sso.test.marker'));
        self::assertSame($root, app());
    }

    /**
     * Jobs run in one queue worker with the scope reset before each.
     *
     * @return void
     */
    public function testOneWorkerRunsJobsInOneApplication(): void
    {
        $this->createWorkerQueue();

        $made = 0;

        $this->app?->scoped(RecordsItsRun::SCOPED, static function () use (&$made): object {
            $made++;

            return new \stdClass;
        });

        try {

            RecordsItsRun::$runs = [];

            dispatch(new RecordsItsRun('a'));
            dispatch(new RecordsItsRun('throw'));
            dispatch(new RecordsItsRun('b'));

            self::assertSame(3, $this->jobsWaiting());

            $this->workNextJob();
            $this->workNextJob();
            $this->workNextJob();
            $this->workNextJob();

            self::assertSame(0, $this->jobsWaiting());
            self::assertSame(['a', 'throw', 'b'], RecordsItsRun::$runs);
            self::assertSame(3, $made);
            self::assertSame($this->app, app());
        } finally {
            $this->dropWorkerQueue();
        }
    }

    /**
     * The worker's loop restores every signal handler it took over.
     *
     * @return void
     */
    public function testTheWorkersLoopLeavesTheSignalsAsTheyWere(): void
    {
        if (!function_exists('pcntl_signal_get_handler')) {
            self::markTestSkipped('The process has no signals to take over without pcntl.');
        }

        $this->createWorkerQueue();

        try {

            $signals = [SIGQUIT, SIGTERM, SIGINT, SIGUSR2, SIGCONT, SIGALRM];
            $before  = array_map(pcntl_signal_get_handler(...), $signals);
            $async   = pcntl_async_signals();

            $this->workNextJob();

            self::assertSame($before, array_map(pcntl_signal_get_handler(...), $signals));
            self::assertSame($async, pcntl_async_signals());
        } finally {
            $this->dropWorkerQueue();
        }
    }

    /**
     * `retainedBy()` finds a value a package object holds, by its path.
     *
     * @return void
     */
    public function testRetainedByFindsWhatAPackageObjectHolds(): void
    {
        $this->app?->instance('sso.test.held', new IdentityReference('App\Models\User', 'a-value-that-must-not-stay'));

        self::assertSame(['sso.test.held->id'], $this->retainedBy(['a-value-that-must-not-stay']));
        self::assertSame([], $this->retainedBy(['anything-else']));
    }

    /**
     * Rows of `[what is held, the value it hides, the path to it]`.
     *
     * @return iterable<string, array{0: object, 1: string, 2: string}>
     */
    public static function provideHiddenValues(): iterable
    {
        $code     = str_repeat('c', HandoffCode::LENGTH);
        $verifier = str_repeat('v', Verifier::MIN_LENGTH);
        $secret   = 'a-secret-that-must-not-stay';

        yield 'a handoff code' => [HandoffCode::fromString($code), $code, 'sso.test.held->value->value'];
        yield 'a verifier' => [Verifier::fromString($verifier), $verifier, 'sso.test.held->value->value'];
        yield 'a secret' => [new Secret($secret), $secret, 'sso.test.held->secret->value'];
    }

    /**
     * `retainedBy()` reads through a `\SensitiveParameterValue`.
     *
     * @param  object  $held
     * @param  string  $value
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideHiddenValues')]
    public function testRetainedByFindsWhatAPackageObjectHides(object $held, string $value, string $path): void
    {
        $this->app?->instance('sso.test.held', $held);

        self::assertSame([$path], $this->retainedBy([$value]));
        self::assertSame([], $this->retainedBy(['anything-else']));
    }

    /**
     * `retainedByStatics()` finds a value in a static property, by its path.
     *
     * @return void
     */
    public function testRetainedByStaticsFindsWhatAPackageClassHolds(): void
    {
        $holder = new class extends SsoModel {
            /** @var string The key of the setting naming a table, for a model to be made. */
            protected const string TABLE = 'connections.table';

            /** @var ?string What the class holds. */
            public static ?string $held = null;
        };

        try {

            self::assertSame([], $this->retainedByStatics(['a-value-that-must-not-stay']));

            $holder::$held = 'a-value-that-must-not-stay';

            self::assertSame([$holder::class . '::$held'], $this->retainedByStatics(['a-value-that-must-not-stay']));
        } finally {
            $holder::$held = null;
        }

        self::assertSame([], $this->retainedByStatics(['a-value-that-must-not-stay']));
    }

    /**
     * Use the lagging replica for the tests of it.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        if (!str_contains($this->name(), 'Replica')) {
            return;
        }

        $this->configureLaggingReplica(app(ConfigRepository::class));
    }

    /**
     * What the call throws, if anything.
     *
     * @param  \Closure(): mixed  $call
     * @return ?\Throwable
     */
    private static function thrownBy(\Closure $call): ?\Throwable
    {
        try {
            $call();
        } catch (\Throwable $exception) {
            return $exception;
        }

        return null;
    }
}
