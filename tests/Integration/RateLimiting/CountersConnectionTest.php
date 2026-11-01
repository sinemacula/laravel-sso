<?php

declare(strict_types = 1);

namespace Tests\Integration\RateLimiting;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Sso\RateLimiting\RateLimitStore;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Integration tests, on whichever engine the suite runs against, of why the
 * counters may live on a connection of their own: an attempt counted inside a
 * transaction on the storage connection that rolls back (a refused flow undoing
 * its work) survives when `sso.rate_limits.connection` names a separate
 * connection, and is rolled back with the transaction when the counters share
 * the storage connection.
 *
 * The separate connection is the storage connection's configuration under
 * another name: another session to the same database on a server engine, so the
 * counters' writes commit on their own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAttemptLimiter::class)]
#[CoversClass(RateLimitStore::class)]
final class CountersConnectionTest extends TestCase
{
    /** @var string Absolute path to the shipped rate limits migration. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var string The table's default name. */
    private const string TABLE = 'sso_rate_limits';

    /** @var string The separate connection the counters are moved to. */
    private const string COUNTERS = 'counters';

    /** @var string The IP address the tests count. */
    private const string IP = '203.0.113.7';

    /**
     * Bind the fixed clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock);
    }

    /**
     * Roll back anything left open, and drop the table from both connections.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        while (DB::transactionLevel() > 0) {
            DB::rollBack();
        }

        config()->set('sso.rate_limits.connection', null);

        Schema::connection(self::COUNTERS)->dropIfExists(self::TABLE);
        Schema::dropIfExists(self::TABLE);

        parent::tearDown();
    }

    /**
     * With the counters on a separate connection, an attempt counted inside a
     * transaction on the storage connection that rolls back is kept: the next
     * attempt finds the limit full.
     *
     * @return void
     */
    public function testACountSurvivesARollbackOnTheStorageConnection(): void
    {
        config()->set('sso.rate_limits.connection', self::COUNTERS);
        config()->set('sso.rate_limits.redemption.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        $this->migration()->up(); // @phpstan-ignore method.notFound

        DB::beginTransaction();

        self::assertTrue($this->limiter()->attempt(AttemptSubject::redemption(self::IP))->isAllowed());

        DB::rollBack();

        self::assertSame(0, DB::transactionLevel());
        self::assertSame(1, DB::connection(self::COUNTERS)->table(self::TABLE)->count());
        self::assertTrue($this->limiter()->attempt(AttemptSubject::redemption(self::IP))->isRateLimited());
    }

    /**
     * With the counters on the storage connection, an attempt counted inside a
     * transaction that rolls back is rolled back with it: the next attempt is
     * allowed again.
     *
     * @return void
     */
    public function testACountIsRolledBackOnTheStorageConnection(): void
    {
        config()->set('sso.rate_limits.redemption.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        $this->migration()->up(); // @phpstan-ignore method.notFound

        DB::beginTransaction();

        self::assertTrue($this->limiter()->attempt(AttemptSubject::redemption(self::IP))->isAllowed());

        DB::rollBack();

        self::assertSame(0, DB::table(self::TABLE)->count());
        self::assertTrue($this->limiter()->attempt(AttemptSubject::redemption(self::IP))->isAllowed());
        self::assertTrue($this->limiter()->attempt(AttemptSubject::redemption(self::IP))->isRateLimited());
    }

    /**
     * With the counters on the storage connection, a refusal inside a
     * transaction leaves it usable: nothing the limiter runs aborts it, on
     * PostgreSQL included, so the statements after it run and commit.
     *
     * @return void
     */
    public function testARefusalLeavesTheStorageTransactionUsable(): void
    {
        config()->set('sso.rate_limits.redemption.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        $this->migration()->up(); // @phpstan-ignore method.notFound

        $results = DB::transaction(function (): array {
            $results = [
                $this->limiter()->attempt(AttemptSubject::redemption(self::IP))->isAllowed(),
                $this->limiter()->attempt(AttemptSubject::redemption(self::IP))->isRateLimited(),
            ];

            DB::table(self::TABLE)->insert(['key' => hash('sha256', 'after'), 'hits' => 1, 'window_ends_at' => '2026-10-31 12:01:00']);

            return $results;
        });

        self::assertSame([true, true], $results);
        self::assertSame(2, DB::table(self::TABLE)->count());
    }

    /**
     * Add the separate connection: the storage connection's configuration under
     * another name.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('database.connections.' . self::COUNTERS, config('database.connections.testing'));
    }

    /**
     * The container's attempt limiter.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\AttemptLimiter
     */
    private function limiter(): AttemptLimiter
    {
        $limiter = $this->app?->make(AttemptLimiter::class);

        self::assertInstanceOf(AttemptLimiter::class, $limiter);

        return $limiter;
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
            self::fail('The rate limits migration did not return a Migration instance.');
        }

        return $migration;
    }
}
