<?php

declare(strict_types = 1);

namespace Tests\Feature\Enforcement;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementFinder;
use SineMacula\Laravel\Sso\Enforcement\EnforcementLock;
use SineMacula\Laravel\Sso\Enforcement\EnforcementSummary;
use SineMacula\Laravel\Sso\Enforcement\LockedEnforcement;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use Tests\Concerns\RecordsLockOrder;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesEnforcement;
use Tests\Fixtures\Enforcement\ScriptedInheritance;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the lock on a tenant's enforcement (SSO-4.5, SSO-4.6): a
 * tenant with no row has one inserted unconfigured (no version, no time of
 * change, off, with no connection) and locked, which every reader answers
 * exactly as no row; an existing row, configured or not, is locked and never
 * changed; no transaction is a `LogicException`. The default contract's
 * `lock()` names the enforcing tenant, locks its row and then the connections
 * the admission goes through and the rule's, in one statement in id order, and
 * answers the policy from the locked rows; while the feature is off it locks,
 * reads and asks nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnforcementLock::class)]
#[CoversClass(LockedEnforcement::class)]
#[CoversClass(DatabaseEnforcement::class)]
#[CoversClass(EnforcementFinder::class)]
#[CoversClass(EnforcementSummary::class)]
final class EnforcementLockTest extends TestCase
{
    use RecordsLockOrder, UsesConnections, UsesEnforcement;

    /** @var string The tenant asked about. */
    private const string TENANT = 'tenant-1';

    /** @var string The application asked about. */
    private const string APPLICATION = 'web';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /**
     * Bind a fixed clock, create the tables and switch the feature on.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $this->clock);

        $this->createConnectionTables();
        $this->createEnforcementTable();

        Config::set('sso.features.enforcement', true);
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropEnforcementTable();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A tenant with no row has one inserted unconfigured, stamped from the
     * clock, and locked: an upsert, then a locking read. The row reads as no
     * row everywhere: the finder finds none, the summary is off with no version
     * or time, and the policy requires nothing, with no version.
     *
     * @return void
     */
    public function testATenantWithNoRowHasAnUnconfiguredRowInsertedAndLocked(): void
    {
        $this->recordLockOrder();

        $row = $this->acquire(self::TENANT);

        self::assertSame(['enforcement upsert', 'enforcement'], $this->lockOrder());
        self::assertSame(self::TENANT, $row->tenant_id);
        self::assertSame(hash('sha256', self::TENANT), $row->tenant_hash);
        self::assertSame(26, strlen($row->id));
        self::assertSame(strtolower($row->id), $row->id);
        self::assertFalse(EnforcementLock::isConfigured($row));

        $stored = TenantEnforcement::query()->sole();

        self::assertSame($row->id, $stored->id);
        self::assertFalse($stored->enabled);
        self::assertSame([], $stored->connection_ids);
        self::assertNull($stored->version);
        self::assertNull($stored->changed_at);
        self::assertSame('2026-11-01T09:30:00+00:00', $stored->created_at->toIso8601String());
        self::assertSame('2026-11-01T09:30:00+00:00', $stored->updated_at->toIso8601String());

        $this->assertReadsAsNoRow();
    }

    /**
     * A configured row is locked and left exactly as it is, however late.
     *
     * @return void
     */
    public function testAConfiguredRowIsLockedAndNeverChanged(): void
    {
        $existing = $this->makeEnforcement(['enabled' => true, 'connection_ids' => ['01jbconnection000000000001']]);
        $before   = $this->rawRow();

        $this->clock->advance(3600);

        $row = $this->acquire(self::TENANT);

        self::assertSame($existing->id, $row->id);
        self::assertTrue(EnforcementLock::isConfigured($row));
        self::assertSame($existing->version, $row->version);
        self::assertSame($before, $this->rawRow());
        self::assertSame(1, TenantEnforcement::query()->count());
    }

    /**
     * An unconfigured row is locked again and left as it is: no second row, no
     * new stamp.
     *
     * @return void
     */
    public function testAnUnconfiguredRowIsLockedAgainAndNeverChanged(): void
    {
        $first  = $this->acquire(self::TENANT);
        $before = $this->rawRow();

        $this->clock->advance(3600);

        $again = $this->acquire(self::TENANT);

        self::assertSame($first->id, $again->id);
        self::assertSame($before, $this->rawRow());
        self::assertSame(1, TenantEnforcement::query()->count());
        $this->assertReadsAsNoRow();
    }

    /**
     * Each tenant has a row of its own, a tenant whose id differs only in case
     * included.
     *
     * @return void
     */
    public function testEachTenantIsLockedThroughARowOfItsOwn(): void
    {
        $lower = $this->acquire('acme');
        $upper = $this->acquire('Acme');

        self::assertNotSame($lower->id, $upper->id);
        self::assertSame('acme', $lower->tenant_id);
        self::assertSame('Acme', $upper->tenant_id);
        self::assertSame(2, TenantEnforcement::query()->count());
    }

    /**
     * With no transaction open on the storage connection, acquiring is a
     * `LogicException`, and nothing is inserted.
     *
     * @return void
     */
    public function testAcquiringOutsideATransactionIsALogicException(): void
    {
        try {
            $this->app?->make(EnforcementLock::class)->acquire(self::TENANT);

            self::fail('A lock was acquired outside a transaction.');
        } catch (\LogicException $exception) {
            self::assertSame('A tenant\'s enforcement is locked inside a transaction on the package\'s storage connection.', $exception->getMessage());
        }

        self::assertSame(0, TenantEnforcement::query()->count());
    }

    /**
     * An empty or overlong tenant id is the application's mistake.
     *
     * @return void
     */
    public function testATenantIdTheTableCannotHoldIsAnInvalidArgument(): void
    {
        foreach (['', str_repeat('t', 256)] as $tenantId) {

            try {
                $this->acquire($tenantId);

                self::fail('A tenant id the table cannot hold was locked.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A tenant id is 1 to 255 bytes.', $exception->getMessage());
            }
        }

        self::assertSame(255, strlen($this->acquire(str_repeat('t', 255))->tenant_id));
    }

    /**
     * While the feature is off, the default contract's lock answers `null` with
     * no statement run and the inheritance contract never asked.
     *
     * @return void
     */
    public function testTheDefaultContractLocksNothingWhileTheFeatureIsOff(): void
    {
        Config::set('sso.features.enforcement', false);

        $inheritance = new ScriptedInheritance([self::TENANT]);

        $this->app?->instance(EnforcementInheritance::class, $inheritance);
        $this->recordLockOrder();

        self::assertNull($this->lock(self::TENANT, ['01jbconnection000000000001']));
        self::assertSame([], $this->lockOrder());
        self::assertSame(0, $this->enforcementStatements());
        self::assertSame([], $inheritance->asked());
        self::assertSame(0, TenantEnforcement::query()->count());
    }

    /**
     * A tenant with no rule is locked through an unconfigured row: the policy
     * requires nothing, with no version, and only the connections given are
     * locked.
     *
     * @return void
     */
    public function testTheDefaultContractLocksATenantWithNoRule(): void
    {
        $connection = $this->enabledConnection();

        $this->recordLockOrder();

        $locked = $this->lock(self::TENANT, [$connection->id]);

        self::assertNotNull($locked);
        self::assertSame(['enforcement upsert', 'enforcement', 'connections ' . $connection->id], $this->lockOrder());
        self::assertNull($locked->rule);
        self::assertSame(self::TENANT, $locked->enforcingTenantId);
        self::assertSame(
            ['tenant_id' => self::TENANT, 'enforcing_tenant_id' => self::TENANT, 'required' => false, 'connection_ids' => [], 'version' => null],
            $locked->policy()->jsonSerialize(),
        );
        self::assertSame($connection->id, $locked->connection(self::TENANT, $connection->id)?->id);
    }

    /**
     * With no connection given and no rule that names one, only the rule's row
     * is locked: no statement locks connections.
     *
     * @return void
     */
    public function testNoConnectionIsLockedWhenNoneIsGivenOrNamed(): void
    {
        $this->recordLockOrder();

        self::assertSame([], $this->locked(self::TENANT, [])->connections);
        self::assertSame(['enforcement upsert', 'enforcement'], $this->lockOrder());
    }

    /**
     * A rule that is off is locked and requires nothing, with its version; its
     * connections are not locked, since none satisfies it.
     *
     * @return void
     */
    public function testTheDefaultContractLocksARuleThatIsOff(): void
    {
        $connection = $this->enabledConnection();
        $named      = $this->enabledConnection();
        $rule       = $this->makeEnforcement(['connection_ids' => [$named->id]]);

        $this->recordLockOrder();

        $locked = $this->locked(self::TENANT, [$connection->id]);

        self::assertSame(['enforcement upsert', 'enforcement', 'connections ' . $connection->id], $this->lockOrder());
        self::assertSame($rule->id, $locked->rule?->id);
        self::assertSame(
            ['tenant_id' => self::TENANT, 'enforcing_tenant_id' => self::TENANT, 'required' => false, 'connection_ids' => [], 'version' => $rule->version],
            $locked->policy()->jsonSerialize(),
        );
    }

    /**
     * A rule that is on is locked with the connections given and the rule's,
     * each once, in one statement in ascending id order; it is satisfied only
     * by those of the enforcing tenant, byte for byte, that are enabled.
     *
     * @return void
     */
    public function testTheDefaultContractLocksARuleThatIsOnWithItsConnectionsInIdOrder(): void
    {
        $last     = $this->enabledConnection(id: 'zzzzzzzzzzzzzzzzzzzzzzzzzz');
        $first    = $this->enabledConnection(id: '00000000000000000000000000');
        $disabled = $this->makeConnection(['id' => '11111111111111111111111111', 'enabled' => false]);
        $foreign  = $this->enabledConnection('Tenant-1', '22222222222222222222222222');
        $rule     = $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$last->id, $disabled->id, $foreign->id, $first->id, '01jbgone000000000000000000']]);

        $this->recordLockOrder();

        $locked = $this->locked(self::TENANT, [$last->id, $first->id]);

        $ids = ['00000000000000000000000000', '01jbgone000000000000000000', '11111111111111111111111111', '22222222222222222222222222', 'zzzzzzzzzzzzzzzzzzzzzzzzzz'];

        self::assertSame(['enforcement upsert', 'enforcement', 'connections ' . implode(', ', $ids)], $this->lockOrder());
        self::assertSame(
            ['tenant_id' => self::TENANT, 'enforcing_tenant_id' => self::TENANT, 'required' => true, 'connection_ids' => [$first->id, $last->id], 'version' => $rule->version],
            $locked->policy()->jsonSerialize(),
        );
        self::assertSame(
            [$first->id, $disabled->id, $foreign->id, $last->id],
            array_map(static fn (Connection $connection): string => $connection->id, $locked->connections),
        );
        self::assertNull($locked->connection(self::TENANT, $foreign->id));
        self::assertSame($foreign->id, $locked->connection('Tenant-1', $foreign->id)?->id);
        self::assertNull($locked->connection(self::TENANT, '01jbgone000000000000000000'));
    }

    /**
     * An inherited rule is the enforcing tenant's: its row is locked, its
     * connections satisfy it, and `isCurrent()` asks the inheritance contract
     * again, true while it still names that tenant and false once it does not.
     *
     * @return void
     */
    public function testTheDefaultContractLocksTheEnforcingTenantsRule(): void
    {
        $inheritance = new ScriptedInheritance(['parent-1', 'parent-1', 'parent-2']);
        $parents     = $this->enabledConnection('parent-1');
        $rule        = $this->makeEnforcement(['tenant_id' => 'parent-1', 'enabled' => true, 'connection_ids' => [$parents->id]]);
        $connection  = $this->enabledConnection();

        $this->app?->instance(EnforcementInheritance::class, $inheritance);

        $locked = $this->locked(self::TENANT, [$connection->id]);

        self::assertSame('parent-1', $locked->enforcingTenantId);
        self::assertSame($rule->id, $locked->rule?->id);
        self::assertSame(self::TENANT, $locked->tenantId);
        self::assertSame(self::APPLICATION, $locked->application);
        self::assertSame([$parents->id], $locked->policy()->connectionIds);
        self::assertFalse($locked->policy()->isSatisfiedBy($connection->id));
        self::assertTrue($locked->isCurrent());
        self::assertFalse($locked->isCurrent());
        self::assertSame(array_fill(0, 3, [self::TENANT, self::APPLICATION]), $inheritance->asked());
        self::assertSame(1, TenantEnforcement::query()->count());
    }

    /**
     * An inheritance contract that names no tenant is a `LogicException` before
     * anything is locked.
     *
     * @return void
     */
    public function testAnInheritanceThatNamesNoTenantLocksNothing(): void
    {
        $this->app?->instance(EnforcementInheritance::class, new ScriptedInheritance(['']));

        try {
            $this->lock(self::TENANT, []);

            self::fail('An inheritance that names no tenant was accepted.');
        } catch (\LogicException $exception) {
            self::assertSame('The enforcement inheritance contract names a tenant of 1 to 255 bytes.', $exception->getMessage());
        }

        self::assertSame(0, TenantEnforcement::query()->count());
    }

    /**
     * An empty application is the application's mistake, asked nothing.
     *
     * @return void
     */
    public function testAnEmptyApplicationIsAnInvalidArgument(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An enforcement policy is asked for an application.');

        DB::connection(StorageConnection::name())->transaction(fn (): ?LockedEnforcement => $this->enforcement()->lock(self::TENANT, '', []));
    }

    /**
     * The unlocked policy and the locked one agree on a stored rule.
     *
     * @return void
     */
    public function testTheLockedPolicyIsTheStoredOne(): void
    {
        $connection = $this->enabledConnection();

        $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$connection->id]]);

        self::assertEquals($this->enforcement()->policy(self::TENANT, self::APPLICATION), $this->locked(self::TENANT, [])->policy());
    }

    /**
     * Assert the tenant reads everywhere as one with no row.
     *
     * @return void
     */
    private function assertReadsAsNoRow(): void
    {
        self::assertNull((new EnforcementFinder)->find(self::TENANT));
        self::assertNotNull((new EnforcementFinder)->row(self::TENANT));
        self::assertEquals(new EnforcementSummary(self::TENANT, false, []), EnforcementSummary::of(self::TENANT, (new EnforcementFinder)->row(self::TENANT)));
        self::assertSame(
            ['tenant_id' => self::TENANT, 'enforcing_tenant_id' => self::TENANT, 'required' => false, 'connection_ids' => [], 'version' => null],
            $this->enforcement()->policy(self::TENANT, self::APPLICATION)->jsonSerialize(),
        );
    }

    /**
     * Acquire the tenant's lock in a transaction on the storage connection.
     *
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Models\TenantEnforcement
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function acquire(string $tenantId): TenantEnforcement
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return DB::connection(StorageConnection::name())->transaction(static fn (): TenantEnforcement => $app->make(EnforcementLock::class)->acquire($tenantId));
    }

    /**
     * Lock the default contract's enforcement of the tenant, on the
     * application, for the connections given, in a transaction on the storage
     * connection.
     *
     * @param  string  $tenantId
     * @param  list<string>  $connectionIds
     * @return ?\SineMacula\Laravel\Sso\Enforcement\LockedEnforcement
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function lock(string $tenantId, array $connectionIds): ?LockedEnforcement
    {
        return DB::connection(StorageConnection::name())->transaction(fn (): ?LockedEnforcement => $this->enforcement()->lock($tenantId, self::APPLICATION, $connectionIds));
    }

    /**
     * Lock as `lock()` does, asserting something was locked.
     *
     * @param  string  $tenantId
     * @param  list<string>  $connectionIds
     * @return \SineMacula\Laravel\Sso\Enforcement\LockedEnforcement
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function locked(string $tenantId, array $connectionIds): LockedEnforcement
    {
        $locked = $this->lock($tenantId, $connectionIds);

        self::assertNotNull($locked, 'Nothing was locked.');

        return $locked;
    }

    /**
     * The tenant's row as the table holds it.
     *
     * @return array<string, mixed>
     */
    private function rawRow(): array
    {
        return (array) DB::connection(StorageConnection::name())->table(StorageConnection::table('enforcement.table'))->where('tenant_id', self::TENANT)->first();
    }

    /**
     * Make an enabled connection of the tenant.
     *
     * @param  string  $tenantId
     * @param  ?string  $id
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function enabledConnection(string $tenantId = self::TENANT, ?string $id = null): Connection
    {
        return $this->makeConnection(['tenant_id' => $tenantId, 'enabled' => true] + ($id === null ? [] : ['id' => $id]));
    }

    /**
     * The default enforcement contract, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement
     */
    private function enforcement(): DatabaseEnforcement
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DatabaseEnforcement::class);
    }
}
