<?php

declare(strict_types = 1);

namespace Tests\Integration\Enforcement;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementFinder;
use SineMacula\Laravel\Sso\Enforcement\EnforcementLock;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RaceFlows;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Enforcement\NearestRuleInheritance;
use Tests\Fixtures\Enforcement\TableSessions;
use Tests\TestCase;

/**
 * Integration tests racing an inherited admission against a rule written on its
 * path and against a tree move. Skipped on SQLite and without `pcntl`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseEnforcement::class)]
#[CoversClass(EnforcementLock::class)]
#[CoversClass(EnforcementService::class)]
final class InheritedEnforcementRaceTest extends TestCase
{
    use RaceFlows, UsesConnections;

    /** @var string The application's tenant tree. */
    public const string TREE = 'sso_test_tenant_parents';

    /** @var string The tenant signing in. */
    private const string TENANT = 'tenant-1';

    /** @var string What an admission reports when it wrote a session. */
    private const string ADMITTED = 'admitted';

    /** @var string What an admission reports when the rule refused it. */
    private const string REFUSED = 'refused';

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the tenant signs in through. */
    private Connection $own;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The middle tenant's connection, the only one its rule allows. */
    private Connection $middle;

    /**
     * Skip where processes cannot share the database, then set up the tree, the
     * sessions, the root's rule and the connections.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpRace();
        $this->usePackageTables();

        Config::set('sso.features.enforcement', true);

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(EnforcementInheritance::class, self::treeInheritance());
        $this->app?->instance(SessionRevocation::class, self::subtreeRevocation());

        self::storageDatabase()->getSchemaBuilder()->create(self::TREE, static function (Blueprint $table): void {
            $table->string('tenant_id')->primary();
            $table->string('parent_id')->nullable();
        });

        TableSessions::create();

        $this->own    = $this->makeConnection(['tenant_id' => self::TENANT, 'enabled' => true, 'has_completed_sign_in' => true]);
        $this->middle = $this->makeConnection(['tenant_id' => 'middle-1', 'enabled' => true, 'has_completed_sign_in' => true]);

        self::assertTrue($this->service()->update('root-1', false, [], Clients::browser())->isChanged());
    }

    /**
     * Remove what the race used and drop its tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->tearDownRace();

        self::storageDatabase()->getSchemaBuilder()->dropIfExists(self::TREE);
        TableSessions::drop();

        parent::tearDown();
    }

    /**
     * Rows of `[the change, whether the admission holds first, whether the
     * one that waits read first]`.
     *
     * @return iterable<string, array{0: string, 1: bool, 2: bool}>
     */
    public static function provideRaces(): iterable
    {
        foreach (['a rule on the path', 'a tree move'] as $change) {
            foreach (['the admission holding first' => true, 'the change holding first' => false] as $order => $admissionFirst) {
                yield "{$change}, {$order}" => [$change, $admissionFirst, false];
                yield "{$change}, {$order}, the waiter reading first" => [$change, $admissionFirst, true];
            }
        }
    }

    /**
     * However the two interleave, no committed session of the tenant breaks the
     * rule that applies to it once both commit.
     *
     * @param  string  $change
     * @param  bool  $admissionFirst
     * @param  bool  $waiterReads
     * @return void
     */
    #[DataProvider('provideRaces')]
    public function testNoSessionSurvivesThatBreaksTheInheritedRule(string $change, bool $admissionFirst, bool $waiterReads): void
    {
        $moving = $change === 'a tree move';

        $this->plant($moving);

        $admission         = fn (): string => $this->admitted();
        $changer           = fn (): string => $moving ? $this->moved() : $this->ruled();
        [$holder, $waiter] = $admissionFirst ? [$admission, $changer] : [$changer, $admission];

        $reports = $this->race([
            fn (): string => $this->holdThenCommit($holder),
            function () use ($waiter): string {

                $this->awaitSignal(self::HOLDS);

                $outcome = $waiter();

                $this->commitSnapshot();

                return $outcome;
            },
        ], null, $this->snapshotsFor([false, $waiterReads], self::reads(...)));

        $reported = (string) json_encode($reports);
        $waited   = $reports[1]['error'] === null;

        self::assertNull($reports[0]['error'], $reported);
        $retrying = $waiterReads && $reports[1]['error'] === self::RACE_SERIALIZATION_FAILURE;

        self::assertTrue($waited || $retrying, 'Only a waiter in its own transaction is left to retry: ' . $reported);
        self::assertSame($admissionFirst ? self::ADMITTED : self::REFUSED, $admissionFirst ? $reports[0]['result'] : ($reports[1]['result'] ?? self::REFUSED), $reported);

        // A change left to retry committed nothing, so the raced session stands
        $sessions = $admissionFirst && !$waited ? [$this->own->id] : [];

        self::assertSame($sessions, TableSessions::connectionsOf(self::TENANT), 'A session survived the rule: ' . $reported);
    }

    /**
     * The inheritance over the tree table, reading each parent with a locking
     * read.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\EnforcementInheritance
     */
    private static function treeInheritance(): EnforcementInheritance
    {
        return new NearestRuleInheritance(static function (string $tenantId): ?string {
            $parent = DB::connection(StorageConnection::name())->table(self::TREE)->where('tenant_id', $tenantId)->sharedLock()->value('parent_id');

            return is_string($parent) ? $parent : null;
        });
    }

    /**
     * A revocation that removes the sessions of the scope's tenant and the two
     * levels of the test tree below it that the policy no longer allows.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SessionRevocation
     */
    private static function subtreeRevocation(): SessionRevocation
    {
        return new readonly class implements SessionRevocation {
            /**
             * Delete the subtree's sessions through a disallowed connection.
             *
             * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
             * @return void
             */
            #[\Override]
            public function revoke(RevocationScope $scope): void
            {
                $database = DB::connection(StorageConnection::name());
                $children = $database->table(InheritedEnforcementRaceTest::TREE)->where('parent_id', $scope->tenantId)->pluck('tenant_id')->all();
                $below    = $database->table(InheritedEnforcementRaceTest::TREE)->whereIn('parent_id', $children)->pluck('tenant_id')->all();

                $database->table(TableSessions::TABLE)
                    ->whereIn('tenant_id', [$scope->tenantId, ...$children, ...$below])
                    ->whereNotIn('connection_id', $scope->policy->connectionIds ?? [])
                    ->delete();
            }
        };
    }

    /**
     * Read every table the race touches, pinning a snapshot.
     *
     * @return void
     */
    private static function reads(): void
    {
        $database = self::storageDatabase();

        $database->table(self::TREE)->get();
        $database->table(TableSessions::TABLE)->get();
        (new EnforcementFinder)->find('middle-1');
    }

    /**
     * Plant the tree: for a move, the tenant under the root with the middle
     * tenant's rule on beside it; else the tenant under the middle one, under
     * the root, with no rule between.
     *
     * @param  bool  $moving
     * @return void
     */
    private function plant(bool $moving): void
    {
        self::storageDatabase()->table(self::TREE)->insert([
            ['tenant_id' => self::TENANT, 'parent_id' => $moving ? 'root-1' : 'middle-1'],
            ['tenant_id' => 'middle-1', 'parent_id' => $moving ? null : 'root-1'],
            ['tenant_id' => 'root-1', 'parent_id' => null],
        ]);

        if (!$moving) {
            return;
        }

        self::assertTrue($this->service()->update('middle-1', true, [$this->middle->id], Clients::browser())->isChanged());
    }

    /**
     * Admit a sign-in through the tenant's own connection, writing its session
     * when the rule allows it; retried whole on a concurrency failure.
     *
     * @return string
     */
    private function admitted(): string
    {
        return self::storageDatabase()->transaction(function (): string {

            $enforcement = app(Enforcement::class);

            self::assertInstanceOf(DatabaseEnforcement::class, $enforcement);

            $locked = $enforcement->lock(self::TENANT, 'web', [$this->own->id]);

            if ($locked?->policy()->isSatisfiedBy($this->own->id) !== true) {
                return self::REFUSED;
            }

            TableSessions::write(self::TENANT, $this->own->id);

            return self::ADMITTED;
        }, 3);
    }

    /**
     * Write the middle tenant's first rule, on, allowing only its connection.
     *
     * @return string
     */
    private function ruled(): string
    {
        return $this->service()->update('middle-1', true, [$this->middle->id], Clients::browser())->status->value;
    }

    /**
     * Move the tenant under the middle tenant, locking its row first, and
     * revoke the sessions the middle tenant's rule does not allow.
     *
     * @return string
     */
    private function moved(): string
    {
        return self::storageDatabase()->transaction(function (): string {

            $this->service()->lockTenants([self::TENANT]);

            self::storageDatabase()->table(self::TREE)->where('tenant_id', self::TENANT)->update(['parent_id' => 'middle-1']);

            app(SessionRevocation::class)->revoke(RevocationScope::tenant(app(Enforcement::class)->policy('middle-1', 'web')));

            return 'moved';
        }, 3);
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
