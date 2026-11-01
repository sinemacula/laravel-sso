<?php

declare(strict_types = 1);

namespace Tests\Integration\SingleUse;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
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
 * Integration tests, on whichever engine the suite runs against, of how the
 * default single-use store behaves inside a caller's transaction on the storage
 * connection: a `seen` key leaves the transaction usable (each statement is a
 * savepoint, which PostgreSQL needs), a record is undone with a transaction
 * that rolls back and kept with one that commits, and a record made outside a
 * transaction is kept whatever that transaction does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseSingleUseStore::class)]
final class SingleUseStoreTransactionTest extends TestCase
{
    /** @var string Absolute path to the shipped single-use keys migration. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The table's default name. */
    private const string TABLE = 'sso_single_use_keys';

    /** @var string A key the tests record. */
    private const string KEY = 'saml-assertion-id';

    /** @var \Tests\Fixtures\FixedClock The clock the store reads. */
    private FixedClock $clock;

    /**
     * Bind the fixed clock and create the shipped table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock;

        $this->app?->instance(Clock::class, $this->clock);

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
     * Inside a transaction on the storage connection, a `seen` key leaves the
     * transaction usable: the refused insert is rolled back to its savepoint,
     * so the statements after it run and commit with the transaction.
     *
     * @return void
     */
    public function testASeenKeyLeavesTheCallersTransactionUsable(): void
    {
        $store = $this->store();

        $outcomes = DB::transaction(function (Connection $connection) use ($store): array {
            $outcomes = [
                $store->record('saml_assertion', self::KEY, $this->until()),
                $store->record('saml_assertion', self::KEY, $this->until()),
            ];

            self::assertSame(1, $connection->transactionLevel());

            $connection->table(self::TABLE)->insert(['namespace' => 'handoff_code', 'key_digest' => hash('sha256', 'after'), 'expires_at' => '2026-10-31 12:01:00']);

            $outcomes[] = $store->record('authorization_request', self::KEY, $this->until());

            return $outcomes;
        });

        self::assertSame([SingleUseOutcome::RECORDED, SingleUseOutcome::SEEN, SingleUseOutcome::RECORDED], $outcomes);
        self::assertSame(3, DB::table(self::TABLE)->count());
        self::assertSame(0, DB::transactionLevel());
    }

    /**
     * An expired key released and recorded again inside a transaction leaves it
     * usable too.
     *
     * @return void
     */
    public function testReleasingAnExpiredKeyLeavesTheCallersTransactionUsable(): void
    {
        $store = $this->store();

        $store->record('saml_assertion', self::KEY, $this->until());

        $this->clock->advance(60);

        $outcomes = DB::transaction(function (Connection $connection) use ($store): array {
            $outcomes = [
                $store->record('saml_assertion', self::KEY, $this->until()),
                $store->record('saml_assertion', self::KEY, $this->until()),
            ];

            $connection->table(self::TABLE)->insert(['namespace' => 'handoff_code', 'key_digest' => hash('sha256', 'after'), 'expires_at' => '2026-10-31 12:02:00']);

            return $outcomes;
        });

        self::assertSame([SingleUseOutcome::RECORDED, SingleUseOutcome::SEEN], $outcomes);
        self::assertSame(2, DB::table(self::TABLE)->count());
    }

    /**
     * A key recorded inside a transaction that rolls back is not held: it can
     * be recorded again afterwards.
     *
     * @return void
     */
    public function testARecordIsUndoneWithATransactionThatRollsBack(): void
    {
        $store = $this->store();

        DB::beginTransaction();

        self::assertSame(SingleUseOutcome::RECORDED, $store->record('saml_assertion', self::KEY, $this->until()));

        DB::rollBack();

        self::assertSame(0, DB::table(self::TABLE)->count());
        self::assertSame(SingleUseOutcome::RECORDED, $store->record('saml_assertion', self::KEY, $this->until()));
    }

    /**
     * A release of an expired key inside a transaction that rolls back is
     * undone with it, and the key can be recorded again afterwards.
     *
     * @return void
     */
    public function testAReleaseIsUndoneWithATransactionThatRollsBack(): void
    {
        $store = $this->store();

        $store->record('saml_assertion', self::KEY, $this->until());

        $this->clock->advance(60);

        DB::beginTransaction();

        self::assertSame(SingleUseOutcome::RECORDED, $store->record('saml_assertion', self::KEY, $this->until()));

        DB::rollBack();

        self::assertSame(['2026-10-31 12:01:00'], DB::table(self::TABLE)->pluck('expires_at')->all());
        self::assertSame(SingleUseOutcome::RECORDED, $store->record('saml_assertion', self::KEY, $this->until()));
        self::assertSame(['2026-10-31 12:02:00'], DB::table(self::TABLE)->pluck('expires_at')->all());
    }

    /**
     * A key recorded inside a transaction that commits is held afterwards.
     *
     * @return void
     */
    public function testARecordIsKeptWithATransactionThatCommits(): void
    {
        $store = $this->store();

        $recorded = DB::transaction(fn (): SingleUseOutcome => $store->record('saml_assertion', self::KEY, $this->until()));

        self::assertSame(SingleUseOutcome::RECORDED, $recorded);
        self::assertSame(SingleUseOutcome::SEEN, $store->record('saml_assertion', self::KEY, $this->until()));
    }

    /**
     * A caller that must keep a consumption whatever happens records outside
     * the transaction it may roll back: the key stays held when that
     * transaction rolls back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecordMadeOutsideTheTransactionSurvivesItsRollback(): void
    {
        $store = $this->store();

        self::assertSame(SingleUseOutcome::RECORDED, $store->record('authorization_request', self::KEY, $this->until()));

        DB::beginTransaction();
        DB::table(self::TABLE)->insert(['namespace' => 'handoff_code', 'key_digest' => hash('sha256', 'handoff'), 'expires_at' => '2026-10-31 12:01:00']);
        DB::rollBack();

        self::assertSame(0, DB::transactionLevel());
        self::assertSame(1, DB::table(self::TABLE)->count());
        self::assertSame(SingleUseOutcome::SEEN, $store->record('authorization_request', self::KEY, $this->until()));
    }

    /**
     * A store on the fixed clock.
     *
     * @return \SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore
     */
    private function store(): DatabaseSingleUseStore
    {
        return new DatabaseSingleUseStore($this->clock);
    }

    /**
     * An expiry a minute after the clock's now.
     *
     * @return \Carbon\CarbonImmutable
     */
    private function until(): CarbonImmutable
    {
        return $this->clock->now()->addMinute();
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
