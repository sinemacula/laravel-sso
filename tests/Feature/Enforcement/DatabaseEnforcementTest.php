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
use SineMacula\Laravel\Sso\Enforcement\LockedEnforcement;
use SineMacula\Laravel\Sso\Exceptions\EnforcementPathChanged;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesEnforcement;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Enforcement\FixedPath;
use Tests\Fixtures\Enforcement\NearestRuleInheritance;
use Tests\Fixtures\Enforcement\ParentInheritance;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\TestCase;

/**
 * Feature tests for the default enforcement contract.
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
     * Bind a fixed clock and a fresh caller, and switch the feature on.
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
     * While the feature is off nothing is required, read or asked.
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
        self::assertSame(self::policyVersion($enforcement->version), $policy->version);
    }

    /**
     * A rule that is on requires its enabled connections, in id order.
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
        self::assertSame(self::policyVersion($enforcement->version, $expected), $policy->version);
        self::assertTrue($policy->isSatisfiedBy($first->id));
    }

    /**
     * Only the enforcing tenant's own enabled connections satisfy a rule.
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
        self::assertSame(self::policyVersion($lower->version, $acme->connectionIds), $acme->version);
        self::assertFalse($other->isRequired());
        self::assertSame(self::policyVersion($upper->version), $other->version);
        self::assertFalse($none->isRequired());
        self::assertNull($none->version);
    }

    /**
     * The policy carries the rule's current version.
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

            $result = $service->update(self::TENANT, $enabled, $ids, Clients::browser());
            $policy = $this->enforcement()->policy(self::TENANT, self::APPLICATION);

            self::assertTrue($result->isChanged(), (string) json_encode($result));
            self::assertSame(self::policyVersion($result->enforcement?->version, $policy->connectionIds), $policy->version);
            self::assertSame($enabled, $policy->isRequired());

            $versions[] = $policy->version;
        }

        self::assertCount(4, array_unique($versions));
    }

    /**
     * Each call reads the row and its connections afresh, and the version moves
     * when a connection is enabled again.
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
        self::assertSame(self::policyVersion('01jbchangedchangedchanged0'), $after->version);
        self::assertTrue($last->isRequired());
        self::assertSame([], $last->connectionIds);
        self::assertSame(self::policyVersion('01jbchangedchangedchanged1'), $last->version);

        $connection->forceFill(['enabled' => true])->save();

        self::assertSame(self::policyVersion('01jbchangedchangedchanged1', [$connection->id]), $contract->policy(self::TENANT, self::APPLICATION)->version);
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
     * The tenant the inheritance contract names is the one whose rule applies.
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
        self::assertSame(self::policyVersion($enforcement->version, [$connection->id]), $child->version);
        self::assertSame('parent', $parent->enforcingTenantId);
    }

    /**
     * Rows of a path the inheritance contract answers for `tenant-1` that is
     * not a path from it.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedPaths(): iterable
    {
        yield 'none' => [[]];
        yield 'another tenant first' => [['tenant-2']];
        yield 'an empty tenant' => [[self::TENANT, '']];
        yield 'a tenant too long' => [[self::TENANT, str_repeat('t', 256)]];
        yield 'a tenant twice' => [[self::TENANT, 'parent-1', self::TENANT]];
        yield 'a tenant that is no string' => [[self::TENANT, 7]];
        yield 'keyed tenants' => [['own' => self::TENANT]];
        yield 'too many tenants' => [[self::TENANT, ...array_map(static fn (int $n): string => "parent-{$n}", range(1, DatabaseEnforcement::MAX_PATH_LENGTH))]];
    }

    /**
     * A path that is not a path from the tenant is a logic error, asked for a
     * policy or a lock, and locks nothing.
     *
     * @param  mixed  $path
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedPaths')]
    public function testAMalformedPathIsALogicError(mixed $path): void
    {
        $this->app?->instance(EnforcementInheritance::class, new FixedPath($path));

        $message = 'The enforcement inheritance contract names a path of 1 to 64 distinct tenants of 1 to 255 bytes, from the tenant asked about.';

        foreach ([fn () => $this->enforcement()->policy(self::TENANT, self::APPLICATION), fn () => $this->locked(self::TENANT)] as $ask) {
            try {
                $ask();

                self::fail('A malformed path was accepted.');
            } catch (\LogicException $exception) {
                self::assertSame($message, $exception->getMessage());
            }
        }

        self::assertSame(0, TenantEnforcement::query()->count());
    }

    /**
     * A lock takes every row of the path, made unconfigured where missing, and
     * judges by the last; the second question reads none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALockTakesEveryRowOfThePathAndJudgesTheLast(): void
    {
        $connection  = $this->enabledConnection('root-1');
        $rule        = $this->makeEnforcement(['tenant_id' => 'root-1', 'enabled' => true, 'connection_ids' => [$connection->id]]);
        $inheritance = new NearestRuleInheritance([self::TENANT => 'middle-1', 'middle-1' => 'root-1']);

        $this->app?->instance(EnforcementInheritance::class, $inheritance);

        $locked = $this->locked(self::TENANT);

        self::assertSame('root-1', $locked->enforcingTenantId);
        self::assertSame($rule->id, $locked->rule?->id);
        self::assertSame([$connection->id], $locked->policy()->connectionIds);
        self::assertSame([2, 0], $inheritance->queries);
        self::assertEqualsCanonicalizing([self::TENANT, 'middle-1', 'root-1'], TenantEnforcement::query()->pluck('tenant_id')->all());
        self::assertSame(1, TenantEnforcement::query()->whereNotNull('version')->count());
    }

    /**
     * A path of the most tenants, the last of the longest id, is a path.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPathAtItsLimitsIsAPath(): void
    {
        $last = str_repeat('r', EnforcementFinder::MAX_TENANT_ID_LENGTH);
        $path = [self::TENANT, ...array_map(static fn (int $n): string => "middle-{$n}", range(1, DatabaseEnforcement::MAX_PATH_LENGTH - 2)), $last];

        $this->app?->instance(EnforcementInheritance::class, new FixedPath($path));

        self::assertSame($last, $this->locked(self::TENANT)->enforcingTenantId);
        self::assertSame(DatabaseEnforcement::MAX_PATH_LENGTH, TenantEnforcement::query()->count());
    }

    /**
     * A path that changes once its rows are locked, by a rule written on a
     * tenant on it, asks for the whole transaction again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPathThatChangesUnderTheLocksIsRetriedWhole(): void
    {
        $this->makeEnforcement(['tenant_id' => 'root-1']);
        $this->app?->instance(EnforcementInheritance::class, new NearestRuleInheritance(
            [self::TENANT => 'middle-1', 'middle-1' => 'root-1'],
            function (int $call): void {
                if ($call !== 1) {
                    return;
                }

                $this->makeEnforcement(['tenant_id' => 'middle-1']);
            },
        ));

        $this->expectException(EnforcementPathChanged::class);

        $this->locked(self::TENANT);
    }

    /**
     * A question of the locked rows about a tenant off the path asks for the
     * whole transaction again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAQuestionOffTheLockedPathIsRetriedWhole(): void
    {
        $this->app?->instance(EnforcementInheritance::class, new readonly class implements EnforcementInheritance {
            /**
             * The tenant alone, once it has asked about another.
             *
             * @param  string  $tenantId
             * @param  string  $application
             * @param  \Closure(string): bool  $isConfigured
             * @return non-empty-list<string>
             */
            #[\Override]
            public function enforcementPath(string $tenantId, string $application, \Closure $isConfigured): array
            {
                $isConfigured('elsewhere');

                return [$tenantId];
            }
        });

        $this->expectException(EnforcementPathChanged::class);

        $this->locked(self::TENANT);
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
     * Rows of `[tenant, application]`: invalid arguments.
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
     * An empty or overlong tenant, or an empty application, is refused.
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
     * The bound contract answers an `EnforcementPolicy`.
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
     * Make an enabled connection of the tenant with a completed sign-in.
     *
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function enabledConnection(string $tenantId = self::TENANT): Connection
    {
        return $this->makeConnection(['tenant_id' => $tenantId, 'enabled' => true, 'has_completed_sign_in' => true]);
    }

    /**
     * The enforcement contract, as the container builds it.
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
     * Lock the tenant's enforcement for `web` in a transaction, asserting
     * something was locked.
     *
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Enforcement\LockedEnforcement
     *
     * @throws \Throwable
     */
    private function locked(string $tenantId): LockedEnforcement
    {
        $locked = DB::connection(StorageConnection::name())->transaction(fn (): ?LockedEnforcement => $this->enforcement()->lock($tenantId, self::APPLICATION, []));

        self::assertNotNull($locked, 'Nothing was locked.');

        return $locked;
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
