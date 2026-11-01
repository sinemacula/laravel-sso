<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;

/**
 * Query budgets for the default single-use store on the paths every assertion,
 * authorisation request and handoff takes: it never reads, and it writes once
 * for a new key, twice for a key it holds, and three times for a key whose row
 * has expired.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseSingleUseStore::class)]
final class SingleUseStoreQueryBudgetTest extends PerformanceContractTestCase
{
    /** @var string The namespace every key is recorded in. */
    private const string KEY_NAMESPACE = 'handoff_code';

    /** @var string The key recorded. */
    private const string KEY = 'the-handoff-code';

    /**
     * A new key is one insert.
     *
     * @return void
     */
    public function testANewKeyIsOneInsert(): void
    {
        $outcome = $this->assertQueryBudget(0, 1, fn (): SingleUseOutcome => $this->record());

        self::assertSame(SingleUseOutcome::RECORDED, $outcome);
    }

    /**
     * A key still held is the insert its index refuses, then a delete of an
     * expired row that removes nothing.
     *
     * @return void
     */
    public function testAHeldKeyIsAnInsertAndADelete(): void
    {
        $this->record();

        $outcome = $this->assertQueryBudget(0, 2, fn (): SingleUseOutcome => $this->record());

        self::assertSame(SingleUseOutcome::SEEN, $outcome);
    }

    /**
     * A key whose row has expired is the refused insert, the delete of the
     * expired row, and the insert that records it again.
     *
     * @return void
     */
    public function testAnExpiredKeyIsAnInsertADeleteAndAnInsert(): void
    {
        $this->record();
        $this->clock->advance(60);

        $outcome = $this->assertQueryBudget(0, 3, fn (): SingleUseOutcome => $this->record());

        self::assertSame(SingleUseOutcome::RECORDED, $outcome);
    }

    /**
     * Record the key for a minute through the container's store.
     *
     * @return \SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome
     */
    private function record(): SingleUseOutcome
    {
        $store = $this->app?->make(SingleUseStore::class);

        self::assertInstanceOf(SingleUseStore::class, $store);

        return $store->record(self::KEY_NAMESPACE, self::KEY, $this->clock->now()->addMinute());
    }
}
