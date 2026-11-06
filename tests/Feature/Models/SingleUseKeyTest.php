<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the single-use key model: its configured table and
 * connection, its shape, and pruning keys whose expiry has passed by the
 * package's clock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SingleUseKey::class)]
final class SingleUseKeyTest extends TestCase
{
    /** @var string The table's default name. */
    private const string TABLE = 'sso_single_use_keys';

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
     * The model takes its table from `sso.single_use.table` and its connection
     * from the storage connection, each time it is built.
     *
     * @return void
     */
    public function testTakesItsTableAndConnectionFromTheSettings(): void
    {
        self::assertSame(self::TABLE, (new SingleUseKey)->getTable());
        self::assertNull((new SingleUseKey)->getConnectionName());

        config()->set('sso.single_use.table', 'replay_keys');
        config()->set('sso.storage.connection', 'package_store');

        self::assertSame('replay_keys', (new SingleUseKey)->getTable());
        self::assertSame('package_store', (new SingleUseKey)->getConnectionName());

        config()->set('sso.rate_limits.connection', 'counters');

        self::assertSame('package_store', (new SingleUseKey)->getConnectionName());
    }

    /**
     * A key has no timestamps, reads its expiry as a date, and accepts no mass
     * assignment.
     *
     * @return void
     */
    public function testHydratesAKey(): void
    {
        DB::table(self::TABLE)->insert(['namespace' => 'handoff_code', 'key_digest' => hash('sha256', 'key'), 'expires_at' => '2026-10-31 12:01:00']);

        $key = SingleUseKey::query()->sole();

        self::assertSame('handoff_code', $key->namespace);
        self::assertSame(hash('sha256', 'key'), $key->key_digest);
        self::assertSame('2026-10-31 12:01:00', $key->expires_at->format('Y-m-d H:i:s'));
        self::assertFalse($key->usesTimestamps());
        self::assertTrue((new SingleUseKey)->isGuarded('namespace'));
        self::assertTrue((new SingleUseKey)->isGuarded('key_digest'));
        self::assertTrue((new SingleUseKey)->isGuarded('expires_at'));
    }

    /**
     * Only keys whose expiry has passed by the bound clock, from the second it
     * names, are prunable.
     *
     * @return void
     */
    public function testPrunableSelectsOnlyExpiredKeysByTheBoundClock(): void
    {
        $this->insertKeys();

        self::assertEqualsCanonicalizing([hash('sha256', 'expired'), hash('sha256', 'expiring')], (new SingleUseKey)->prunable()->pluck('key_digest')->all());

        $this->app?->instance(Clock::class, new FixedClock('2026-10-31T11:00:00Z'));

        self::assertSame([], (new SingleUseKey)->prunable()->pluck('key_digest')->all());
    }

    /**
     * The clock's instant is compared, whatever timezone it answers in.
     *
     * @return void
     */
    public function testPrunableComparesTheClockAsAnInstant(): void
    {
        $this->insertKeys();

        $this->app?->instance(Clock::class, new FixedClock('2026-10-31T21:00:00+09:00'));

        self::assertEqualsCanonicalizing([hash('sha256', 'expired'), hash('sha256', 'expiring')], (new SingleUseKey)->prunable()->pluck('key_digest')->all());
    }

    /**
     * Pruning deletes only the expired keys.
     *
     * @return void
     */
    public function testPruningDeletesOnlyExpiredKeys(): void
    {
        $this->insertKeys();

        self::assertSame(2, (new SingleUseKey)->pruneAll());
        self::assertSame([hash('sha256', 'held')], DB::table(self::TABLE)->pluck('key_digest')->all());
    }

    /**
     * `model:prune`, naming the model, deletes only the expired keys.
     *
     * @return void
     */
    public function testModelPruneDeletesOnlyExpiredKeys(): void
    {
        $this->insertKeys();

        Artisan::call('model:prune', ['--model' => [SingleUseKey::class]]);

        self::assertSame([hash('sha256', 'held')], DB::table(self::TABLE)->pluck('key_digest')->all());
    }

    /**
     * Insert a key that expired a second before the fixed clock's now, one that
     * expires at it, and one that expires a second after it.
     *
     * @return void
     */
    private function insertKeys(): void
    {
        DB::table(self::TABLE)->insert([
            ['namespace' => 'handoff_code', 'key_digest' => hash('sha256', 'expired'), 'expires_at' => '2026-10-31 11:59:59'],
            ['namespace' => 'handoff_code', 'key_digest' => hash('sha256', 'expiring'), 'expires_at' => '2026-10-31 12:00:00'],
            ['namespace' => 'handoff_code', 'key_digest' => hash('sha256', 'held'), 'expires_at' => '2026-10-31 12:00:01'],
        ]);
    }
}
