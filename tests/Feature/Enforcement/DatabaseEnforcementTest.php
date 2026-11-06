<?php

declare(strict_types = 1);

namespace Tests\Feature\Enforcement;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementFinder;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Models\Connection;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesEnforcement;
use Tests\Fixtures\Enforcement\ParentInheritance;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\TestCase;

/**
 * Feature tests for the default enforcement contract (SSO-4.1, SSO-4.2,
 * SSO-4.6): nothing is required, with nothing read, while the feature is off;
 * otherwise the enforcing tenant's stored rule is read on the write connection
 * on every call, and only its enabled connections, of that tenant byte for
 * byte, satisfy it, with the rule's version.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseEnforcement::class)]
#[CoversClass(EnforcementFinder::class)]
final class DatabaseEnforcementTest extends TestCase
{
    use UsesConnections, UsesEnforcement;

    /** @var string The tenant asked about. */
    private const string TENANT = 'tenant-1';

    /** @var string The application asked about. */
    private const string APPLICATION = 'web';

    /**
     * Bind a fixed clock and a fresh caller, create the tables and switch the
     * feature on.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, new RecordingFreshness);

        $this->usePackageTables();

        Config::set('sso.features.enforcement', true);
    }

    /**
     * While the feature is off nothing is required, and nothing is read or
     * asked, whatever is stored.
     *
     * @return void
     */
    public function testRequiresNothingAndReadsNothingWhileTheFeatureIsOff(): void
    {
        $connection  = $this->enabledConnection();
        $inheritance = new ParentInheritance;

        $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$connection->id]]);
        $this->app?->instance(EnforcementInheritance::class, $inheritance);

        Config::set('sso.features.enforcement', false);

        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        $policy = $this->enforcement()->policy(self::TENANT, self::APPLICATION);

        self::assertSame(0, $queries);
        self::assertSame([], $inheritance->asked());
        self::assertSame(
            ['tenant_id' => self::TENANT, 'enforcing_tenant_id' => self::TENANT, 'required' => false, 'connection_ids' => [], 'version' => null],
            $policy->jsonSerialize(),
        );
    }

    /**
     * A tenant with no rule stored requires nothing, with no version.
     *
     * @return void
     */
    public function testATenantWithNoRuleRequiresNothing(): void
    {
        $policy = $this->enforcement()->policy(self::TENANT, self::APPLICATION);

        self::assertFalse($policy->isRequired());
        self::assertSame(self::TENANT, $policy->enforcingTenantId);
        self::assertSame([], $policy->connectionIds);
        self::assertNull($policy->version);
    }

    /**
     * A rule that is off requires nothing, and carries its version.
     *
     * @return void
     */
    public function testARuleThatIsOffRequiresNothingWithItsVersion(): void
    {
        $connection  = $this->enabledConnection();
        $enforcement = $this->makeEnforcement(['enabled' => false, 'connection_ids' => [$connection->id]]);

        $policy = $this->enforcement()->policy(self::TENANT, self::APPLICATION);

        self::assertFalse($policy->isRequired());
        self::assertSame([], $policy->connectionIds);
        self::assertSame($enforcement->version, $policy->version);
    }

    /**
     * A rule that is on requires one of its enabled connections, in id order,
     * and carries its version.
     *
     * @return void
     */
    public function testARuleThatIsOnRequiresItsEnabledConnections(): void
    {
        $first       = $this->enabledConnection();
        $second      = $this->enabledConnection();
        $enforcement = $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$second->id, $first->id]]);
        $expected    = [$first->id, $second->id];

        sort($expected, SORT_STRING);

        $policy = $this->enforcement()->policy(self::TENANT, self::APPLICATION);

        self::assertTrue($policy->isRequired());
        self::assertSame(self::TENANT, $policy->tenantId);
        self::assertSame(self::TENANT, $policy->enforcingTenantId);
        self::assertSame($expected, $policy->connectionIds);
        self::assertSame($enforcement->version, $policy->version);
        self::assertTrue($policy->isSatisfiedBy($first->id));
    }

    /**
     * Only the enforcing tenant's own enabled connections satisfy it: a
     * disabled one, another tenant's id stored in the list, a tenant whose id
     * differs only in case, and an id with no connection are all left out. A
     * rule left with none is still required, and satisfied by none.
     *
     * @return void
     */
    public function testOnlyTheEnforcingTenantsEnabledConnectionsSatisfyIt(): void
    {
        $enabled  = $this->enabledConnection();
        $disabled = $this->makeConnection(['enabled' => false, 'has_completed_sign_in' => true]);
        $other    = $this->enabledConnection('tenant-2');
        $variant  = $this->enabledConnection('Tenant-1');

        $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$enabled->id, $disabled->id, $other->id, $variant->id, '01jbzzzzzzzzzzzzzzzzzzzzzz']]);

        $policy = $this->enforcement()->policy(self::TENANT, self::APPLICATION);

        self::assertTrue($policy->isRequired());
        self::assertSame([$enabled->id], $policy->connectionIds);
        self::assertFalse($policy->isSatisfiedBy($variant->id));

        $enabled->forceFill(['enabled' => false])->save();

        $none = $this->enforcement()->policy(self::TENANT, self::APPLICATION);

        self::assertTrue($none->isRequired());
        self::assertSame([], $none->connectionIds);
        self::assertFalse($none->isSatisfiedBy($enabled->id));
    }

    /**
     * Tenants whose ids differ only in case have rules of their own.
     *
     * @return void
     */
    public function testTenantsWhoseIdsDifferInCaseHaveRulesOfTheirOwn(): void
    {
        $connection = $this->enabledConnection('acme');
        $upper      = $this->makeEnforcement(['tenant_id' => 'Acme', 'enabled' => false]);
        $lower      = $this->makeEnforcement(['tenant_id' => 'acme', 'enabled' => true, 'connection_ids' => [$connection->id]]);

        $acme  = $this->enforcement()->policy('acme', self::APPLICATION);
        $other = $this->enforcement()->policy('Acme', self::APPLICATION);
        $none  = $this->enforcement()->policy('ACME', self::APPLICATION);

        self::assertTrue($acme->isRequired());
        self::assertSame($lower->version, $acme->version);
        self::assertFalse($other->isRequired());
        self::assertSame($upper->version, $other->version);
        self::assertFalse($none->isRequired());
        self::assertNull($none->version);
    }

    /**
     * The policy carries the version the rule now has, which changes with every
     * update.
     *
     * @return void
     */
    public function testTheVersionChangesWithEveryUpdate(): void
    {
        $connection = $this->enabledConnection();
        $other      = $this->enabledConnection();
        $service    = $this->service();

        $versions = [];

        foreach ([[true, [$connection->id]], [true, [$connection->id, $other->id]], [false, [$connection->id]], [true, [$other->id]]] as [$enabled, $ids]) {

            $result = $service->update(self::TENANT, $enabled, $ids);
            $policy = $this->enforcement()->policy(self::TENANT, self::APPLICATION);

            self::assertTrue($result->isChanged(), (string) json_encode($result));
            self::assertSame($result->enforcement?->version, $policy->version);
            self::assertSame($enabled, $policy->isRequired());

            $versions[] = $policy->version;
        }

        self::assertCount(4, array_unique($versions));
    }

    /**
     * One instance answers from the row as it is at each call, never from what
     * it read before.
     *
     * @return void
     */
    public function testAnswersFromTheRowAsItIsAtEachCall(): void
    {
        $connection  = $this->enabledConnection();
        $enforcement = $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$connection->id]]);
        $contract    = $this->enforcement();

        $before = $contract->policy(self::TENANT, self::APPLICATION);

        $enforcement->forceFill(['enabled' => false, 'version' => '01jbchangedchangedchanged0'])->save();

        $after = $contract->policy(self::TENANT, self::APPLICATION);

        $connection->forceFill(['enabled' => false])->save();
        $enforcement->forceFill(['enabled' => true, 'version' => '01jbchangedchangedchanged1'])->save();

        $last = $contract->policy(self::TENANT, self::APPLICATION);

        self::assertTrue($before->isRequired());
        self::assertFalse($after->isRequired());
        self::assertSame('01jbchangedchangedchanged0', $after->version);
        self::assertTrue($last->isRequired());
        self::assertSame([], $last->connectionIds);
        self::assertSame('01jbchangedchangedchanged1', $last->version);
    }

    /**
     * Every read is on the write connection.
     *
     * @return void
     */
    public function testReadsTheWriteConnection(): void
    {
        $connection = $this->enabledConnection();
        $contract   = $this->enforcement();

        $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$connection->id]]);

        DB::connection(StorageConnection::name())->setReadPdo(static function (): never {
            throw new \LogicException('The read connection was used.');
        });

        try {
            $policy = $contract->policy(self::TENANT, self::APPLICATION);
            $none   = $contract->policy('tenant-2', self::APPLICATION);
        } finally {
            DB::connection(StorageConnection::name())->setReadPdo(null);
        }

        self::assertSame([$connection->id], $policy->connectionIds);
        self::assertFalse($none->isRequired());
    }

    /**
     * The inheritance contract bound is asked, and the tenant it names is the
     * one whose rule and connections apply.
     *
     * @return void
     */
    public function testTheBoundInheritanceNamesTheEnforcingTenant(): void
    {
        $inheritance = new ParentInheritance(['child' => 'parent']);
        $connection  = $this->enabledConnection('parent');
        $own         = $this->enabledConnection('child');
        $enforcement = $this->makeEnforcement(['tenant_id' => 'parent', 'enabled' => true, 'connection_ids' => [$connection->id, $own->id]]);

        $this->makeEnforcement(['tenant_id' => 'child', 'enabled' => false]);
        $this->app?->instance(EnforcementInheritance::class, $inheritance);

        $child  = $this->enforcement()->policy('child', 'mobile');
        $parent = $this->enforcement()->policy('parent', self::APPLICATION);

        self::assertSame([['child', 'mobile'], ['parent', self::APPLICATION]], $inheritance->asked());
        self::assertTrue($child->isRequired());
        self::assertSame('child', $child->tenantId);
        self::assertSame('parent', $child->enforcingTenantId);
        self::assertSame([$connection->id], $child->connectionIds);
        self::assertSame($enforcement->version, $child->version);
        self::assertSame('parent', $parent->enforcingTenantId);
    }

    /**
     * An inheritance contract that names no tenant is a logic error, never an
     * answer that nothing is required.
     *
     * @return void
     */
    public function testAnInheritanceThatNamesNoTenantIsALogicError(): void
    {
        $this->app?->instance(EnforcementInheritance::class, new ParentInheritance([self::TENANT => '']));

        $this->expectException(\LogicException::class);

        $this->enforcement()->policy(self::TENANT, self::APPLICATION);
    }

    /**
     * A malformed feature switch fails closed.
     *
     * @return void
     */
    public function testAMalformedFeatureSwitchThrows(): void
    {
        Config::set('sso.features.enforcement', 'sometimes');

        $this->expectException(\InvalidArgumentException::class);

        $this->enforcement()->policy(self::TENANT, self::APPLICATION);
    }

    /**
     * Rows of `[tenant, application]`: what the application may not ask about.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function provideMistakes(): iterable
    {
        yield 'empty tenant' => ['', self::APPLICATION];
        yield 'overlong tenant' => [str_repeat('t', 256), self::APPLICATION];
        yield 'empty application' => [self::TENANT, ''];
    }

    /**
     * An empty or overlong tenant, or an empty application, is the caller's
     * mistake, whether the feature is on or off.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @return void
     */
    #[DataProvider('provideMistakes')]
    public function testAMistakenQuestionIsAnInvalidArgument(string $tenantId, string $application): void
    {
        foreach ([true, false] as $feature) {

            Config::set('sso.features.enforcement', $feature);

            try {
                $this->enforcement()->policy($tenantId, $application);
                self::fail('The question was answered.');
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    /**
     * A database error propagates; it is never read as nothing being required.
     *
     * @return void
     */
    public function testADatabaseErrorPropagates(): void
    {
        Schema::connection(StorageConnection::name())->dropIfExists(StorageConnection::table('enforcement.table'));

        $this->expectException(QueryException::class);

        $this->enforcement()->policy(self::TENANT, self::APPLICATION);
    }

    /**
     * The policy the bound contract answers is an `EnforcementPolicy` of the
     * default store.
     *
     * @return void
     */
    public function testTheDefaultIsBound(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app   = $this->app;
        $bound = $app->make(Enforcement::class);

        self::assertInstanceOf(DatabaseEnforcement::class, $bound);
        self::assertInstanceOf(EnforcementPolicy::class, $bound->policy(self::TENANT, self::APPLICATION));
    }

    /**
     * Make an enabled connection, with a completed sign-in, of the tenant.
     *
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function enabledConnection(string $tenantId = self::TENANT): Connection
    {
        return $this->makeConnection(['tenant_id' => $tenantId, 'enabled' => true, 'has_completed_sign_in' => true]);
    }

    /**
     * The enforcement contract, as the container builds it: the default store.
     *
     * @return \SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement
     */
    private function enforcement(): DatabaseEnforcement
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app         = $this->app;
        $enforcement = $app->make(Enforcement::class);

        self::assertInstanceOf(DatabaseEnforcement::class, $enforcement);

        return $enforcement;
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
