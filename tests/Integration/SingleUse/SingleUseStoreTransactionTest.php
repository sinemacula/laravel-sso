<?php

declare(strict_types = 1);

namespace Tests\Integration\SingleUse;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Integration tests of the single-use store inside a caller's transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseSingleUseStore::class)]
final class SingleUseStoreTransactionTest extends TestCase
{
    /** @var string The table's default name. */
    private const string TABLE = 'sso_single_use_keys';

    /** @var string A key the tests record. */
    private const string KEY = 'saml-assertion-id';

    /** @var \Tests\Fixtures\FixedClock The clock the store reads. */
    private FixedClock $clock;

    /**
     * Bind the fixed clock and give the test the package's tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock;

        $this->app?->instance(Clock::class, $this->clock);

        $this->usePackageTables();
    }

    /**
     * A `seen` key leaves the caller's transaction usable, its insert rolled
     * back to a savepoint.
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
     * Releasing an expired key leaves the caller's transaction usable.
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
     * A record is undone with a transaction that rolls back.
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
     * A release is undone with a transaction that rolls back.
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
     * A record made outside the transaction survives its rollback.
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
}
