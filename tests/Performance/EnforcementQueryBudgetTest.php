<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementFinder;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\EnforcementResult;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Enforcement\EnforcementSummary;
use SineMacula\Laravel\Sso\Enforcement\Enums\EnforcementStatus;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Models\Connection;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Freshness\RecordingFreshness;

/**
 * Query budgets for enforcement (SSO-4.1, SSO-4.5, SSO-4.6). The contract reads
 * the enforcing tenant's row on every call, and its connections only when the
 * rule is on; a change reads each connection given and the tenant's row before
 * freshness is asked, then again in its transaction under the locks, and writes
 * only what it changes:
 *
 * - `policy()`: none while the feature is off; 1 read with no rule, or a rule
 *   that is off; 2 reads (the row, then its connections) with a rule on;
 * - `update()` making a tenant's first change: 4 reads (the connection and the
 *   row; then, locked, the row and the connection) and 2 writes (the upsert
 *   that creates the row unless it exists, and the update);
 * - `update()` changing a stored rule: the same 4 reads and 1 write;
 * - `update()` giving what is stored: 2 reads; refused by a stale caller or for
 *   want of a completed sign-in: 2 reads; refused while the feature is off:
 *   nothing; an unknown id: 1 read;
 * - `get()`: 1 read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseEnforcement::class)]
#[CoversClass(EnforcementService::class)]
#[CoversClass(EnforcementFinder::class)]
final class EnforcementQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections;

    /** @var string The tenant whose enforcement is read and changed. */
    private const string TENANT = 'tenant-1';

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract the helper asks. */
    private RecordingFreshness $freshness;

    /** @var \SineMacula\Laravel\Sso\Models\Connection An enabled connection of the tenant that has completed a sign-in. */
    private Connection $connection;

    /**
     * Bind a freshness contract that answers `fresh`, switch the feature on and
     * make a connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = new RecordingFreshness;

        $this->app?->instance(Freshness::class, $this->freshness);

        Config::set('sso.features.enforcement', true);

        $this->connection = $this->makeConnection(['enabled' => true, 'has_completed_sign_in' => true]);
    }

    /**
     * The contract reads nothing while the feature is off, the row alone while
     * the rule is absent or off, and the row and its connections while it is
     * on.
     *
     * @return void
     */
    public function testThePolicyReadsTheRowAndItsConnections(): void
    {
        $contract = $this->enforcement();

        Config::set('sso.features.enforcement', false);

        $off = $this->assertQueryBudget(0, 0, fn (): EnforcementPolicy => $contract->policy(self::TENANT, 'web'));

        Config::set('sso.features.enforcement', true);

        $none = $this->assertQueryBudget(1, 0, fn (): EnforcementPolicy => $contract->policy(self::TENANT, 'web'));

        $this->service()->update(self::TENANT, false, [$this->connection->id]);

        $stored = $this->assertQueryBudget(1, 0, fn (): EnforcementPolicy => $contract->policy(self::TENANT, 'web'));

        $this->service()->update(self::TENANT, true, [$this->connection->id]);

        $on = $this->assertQueryBudget(2, 0, fn (): EnforcementPolicy => $contract->policy(self::TENANT, 'web'));

        self::assertFalse($off->isRequired());
        self::assertNull($none->version);
        self::assertNotNull($stored->version);
        self::assertSame([$this->connection->id], $on->connectionIds);
    }

    /**
     * A tenant's first change is four reads, the upsert and the update; a later
     * change the same reads and the update.
     *
     * @return void
     */
    public function testAChangeIsFourReadsAndItsWrites(): void
    {
        $created = $this->assertQueryBudget(4, 2, fn (): EnforcementResult => $this->turnOn());

        $off = $this->assertQueryBudget(4, 1, fn (): EnforcementResult => $this->service()->update(self::TENANT, false, [$this->connection->id]));

        self::assertSame(EnforcementStatus::UPDATED, $created->status);
        self::assertSame(EnforcementStatus::UPDATED, $off->status);
    }

    /**
     * A change that gives what is stored is a change's four reads, the last two
     * locked to confirm it, and a refusal stops where it is decided, with no
     * write.
     *
     * @return void
     */
    public function testAnUnchangedOrRefusedChangeWritesNothing(): void
    {
        $this->turnOn();

        $unchanged = $this->assertQueryBudget(4, 0, fn (): EnforcementResult => $this->turnOn());

        $untried = $this->makeConnection(['enabled' => true]);
        $lacking = $this->assertQueryBudget(2, 0, fn (): EnforcementResult => $this->service()->update(self::TENANT, true, [$untried->id]));
        $unknown = $this->assertQueryBudget(1, 0, fn (): EnforcementResult => $this->service()->update(self::TENANT, true, ['01jbzzzzzzzzzzzzzzzzzzzzzz']));

        $this->freshness->answer(FreshnessOutcome::STALE);

        $stale = $this->assertQueryBudget(2, 0, fn (): EnforcementResult => $this->service()->update(self::TENANT, false, [$this->connection->id]));

        Config::set('sso.features.enforcement', false);

        $disabled = $this->assertQueryBudget(0, 0, fn (): EnforcementResult => $this->turnOn());

        self::assertSame(EnforcementStatus::UNCHANGED, $unchanged->status);
        self::assertSame(FailureReason::COMPLETED_SIGN_IN_REQUIRED, $lacking->reason);
        self::assertTrue($unknown->isInvalid());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $stale->reason);
        self::assertSame(FailureReason::FEATURE_DISABLED, $disabled->reason);
    }

    /**
     * Reading the tenant's enforcement is one read.
     *
     * @return void
     */
    public function testGetIsOneRead(): void
    {
        $this->turnOn();

        $summary = $this->assertQueryBudget(1, 0, fn (): EnforcementSummary => $this->service()->get(self::TENANT));

        self::assertTrue($summary->enabled);
    }

    /**
     * Turn the tenant's enforcement on, satisfied by its connection.
     *
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementResult
     */
    private function turnOn(): EnforcementResult
    {
        return $this->service()->update(self::TENANT, true, [$this->connection->id]);
    }

    /**
     * The enforcement contract, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\Enforcement
     */
    private function enforcement(): Enforcement
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(Enforcement::class);
    }

    /**
     * The enforcement helper, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementService
     */
    private function service(): EnforcementService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(EnforcementService::class);
    }
}
