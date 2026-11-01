<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Models\RateLimit;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the attempt counter model: its configured table and
 * connection, its shape, and pruning counters whose window has ended by the
 * package's clock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RateLimit::class)]
final class RateLimitTest extends TestCase
{
    /** @var string Absolute path to the shipped rate limits migration. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var string The table's default name. */
    private const string TABLE = 'sso_rate_limits';

    /**
     * Bind the fixed clock and create the shipped table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock);

        $this->migration()->up(); // @phpstan-ignore method.notFound
    }

    /**
     * Drop the shipped table, so a persistent database starts the next test
     * without it.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(self::TABLE);

        parent::tearDown();
    }

    /**
     * The model takes its table from `sso.rate_limits.table` and its connection
     * from `sso.rate_limits.connection`, or the storage connection when that
     * names none, each time it is built.
     *
     * @return void
     */
    public function testTakesItsTableAndConnectionFromTheSettings(): void
    {
        self::assertSame(self::TABLE, (new RateLimit)->getTable());
        self::assertNull((new RateLimit)->getConnectionName());

        config()->set('sso.rate_limits.table', 'attempt_counters');
        config()->set('sso.storage.connection', 'package_store');

        self::assertSame('attempt_counters', (new RateLimit)->getTable());
        self::assertSame('package_store', (new RateLimit)->getConnectionName());

        config()->set('sso.rate_limits.connection', 'counters');

        self::assertSame('counters', (new RateLimit)->getConnectionName());

        config()->set('sso.rate_limits.connection', '');

        self::assertSame('package_store', (new RateLimit)->getConnectionName());
    }

    /**
     * A counters connection that is not a name is refused, rather than counting
     * on another connection.
     *
     * @return void
     */
    public function testRefusesACountersConnectionThatIsNotAName(): void
    {
        config()->set('sso.rate_limits.connection', ['counters']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`sso.rate_limits.connection` must be a connection name, or null or empty for the storage connection.');

        new RateLimit;
    }

    /**
     * A counter is keyed by its digest, has no timestamps, reads its count as
     * an integer and its window's end as a date, and accepts no mass
     * assignment.
     *
     * @return void
     */
    public function testHydratesACounter(): void
    {
        $key = hash('sha256', 'counter');

        DB::table(self::TABLE)->insert(['key' => $key, 'hits' => 3, 'window_ends_at' => '2026-10-31 12:01:00']);

        $counter = RateLimit::query()->findOrFail($key);

        self::assertSame($key, $counter->key);
        self::assertSame($key, $counter->getKey());
        self::assertSame(3, $counter->hits);
        self::assertSame('2026-10-31 12:01:00', $counter->window_ends_at->format('Y-m-d H:i:s'));
        self::assertSame('key', $counter->getKeyName());
        self::assertSame('string', $counter->getKeyType());
        self::assertFalse($counter->getIncrementing());
        self::assertFalse($counter->usesTimestamps());
        self::assertTrue((new RateLimit)->isGuarded('key'));
        self::assertTrue((new RateLimit)->isGuarded('hits'));
        self::assertTrue((new RateLimit)->isGuarded('window_ends_at'));
    }

    /**
     * Only counters whose window has ended by the bound clock, from the second
     * it names, are prunable.
     *
     * @return void
     */
    public function testPrunableSelectsOnlyEndedWindowsByTheBoundClock(): void
    {
        $this->insertCounters();

        self::assertEqualsCanonicalizing([hash('sha256', 'ended'), hash('sha256', 'ending')], $this->prunableKeys());

        $this->app?->instance(Clock::class, new FixedClock('2026-10-31T11:00:00Z'));

        self::assertSame([], $this->prunableKeys());

        $this->app?->instance(Clock::class, new FixedClock('2026-10-31T12:00:01Z'));

        self::assertEqualsCanonicalizing([hash('sha256', 'ended'), hash('sha256', 'ending'), hash('sha256', 'live')], $this->prunableKeys());
    }

    /**
     * The clock's instant is compared, whatever timezone it answers in.
     *
     * @return void
     */
    public function testPrunableComparesTheClockAsAnInstant(): void
    {
        $this->insertCounters();

        $this->app?->instance(Clock::class, new FixedClock('2026-10-31T21:00:00+09:00'));

        self::assertEqualsCanonicalizing([hash('sha256', 'ended'), hash('sha256', 'ending')], $this->prunableKeys());
    }

    /**
     * `model:prune`, naming the model, deletes only the counters whose window
     * has ended.
     *
     * @return void
     */
    public function testModelPruneDeletesOnlyEndedWindows(): void
    {
        $this->insertCounters();

        Artisan::call('model:prune', ['--model' => [RateLimit::class]]);

        self::assertSame([hash('sha256', 'live')], DB::table(self::TABLE)->pluck('key')->all());
    }

    /**
     * Insert a counter whose window ended a second before the fixed clock's
     * now, one that ends at it, and one that ends a second after it.
     *
     * @return void
     */
    private function insertCounters(): void
    {
        DB::table(self::TABLE)->insert([
            ['key' => hash('sha256', 'ended'), 'hits' => 1, 'window_ends_at' => '2026-10-31 11:59:59'],
            ['key' => hash('sha256', 'ending'), 'hits' => 2, 'window_ends_at' => '2026-10-31 12:00:00'],
            ['key' => hash('sha256', 'live'), 'hits' => 3, 'window_ends_at' => '2026-10-31 12:00:01'],
        ]);
    }

    /**
     * The keys of the counters the model would prune now, by the bound clock.
     *
     * @return array<mixed>
     *
     * @phpstan-impure
     */
    private function prunableKeys(): array
    {
        return (new RateLimit)->prunable()->pluck('key')->all();
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
