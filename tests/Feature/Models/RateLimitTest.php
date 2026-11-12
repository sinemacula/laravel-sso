<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Models\RateLimit;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the attempt counter model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RateLimit::class)]
final class RateLimitTest extends TestCase
{
    /** @var string The table's default name. */
    private const string TABLE = 'sso_rate_limits';

    /**
     * Bind the fixed clock and give the test the package's tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock);

        $this->usePackageTables();
    }

    /**
     * The model reads its table and connection from the settings each time it
     * is built.
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
     * A counters connection that is not a name is refused.
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
     * A counter is keyed by its digest, has no timestamps and casts its
     * columns.
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
     * Only counters whose window ended by the bound clock are prunable.
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
     * `model:prune` deletes only the counters whose window has ended.
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
     * Insert counters ending a second before, at, and a second after the fixed
     * now.
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
}
