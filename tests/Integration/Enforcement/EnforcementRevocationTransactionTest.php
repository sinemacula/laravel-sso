<?php

declare(strict_types = 1);

namespace Tests\Integration\Enforcement;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\EnforcementEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\EnforcementResult;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Integration tests, on a real database, that an enforcement change and the
 * session revocation it needs commit or roll back together (SSO-4.5, SSO-10.5,
 * decision D5): a revocation that writes through the storage connection and
 * succeeds commits with the change; one that writes and then throws leaves
 * neither its write nor the change, and nothing is reported; and inside a
 * transaction the application opened, a rollback undoes both though the helper
 * succeeded.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnforcementService::class)]
#[CoversClass(EnforcementEvents::class)]
final class EnforcementRevocationTransactionTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /** @var string The table the revocation writes to, as an adapter writes its revoked sessions. */
    private const string REVOKED = 'example_revoked_sessions';

    /** @var string The tenant whose enforcement changes. */
    private const string TENANT = 'tenant-1';

    /** @var \SineMacula\Laravel\Sso\Models\Connection An enabled connection of the tenant that has completed a sign-in. */
    private Connection $connection;

    /**
     * Bind a fixed clock and a fresh caller, create the tables, a connection
     * and the revocation's table, switch the feature on and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $this->usePackageTables();

        Schema::connection(StorageConnection::name())->create(self::REVOKED, static function (Blueprint $table): void {
            $table->id();
            $table->string('tenant_id');
            $table->char('version', 26);
        });

        Config::set('sso.features.enforcement', true);

        $this->connection = $this->makeConnection(['enabled' => true, 'has_completed_sign_in' => true]);

        $this->startRecordingEvents();
    }

    /**
     * Drop the table the revocation writes to.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::connection(StorageConnection::name())->dropIfExists(self::REVOKED);

        parent::tearDown();
    }

    /**
     * A revocation that writes and succeeds commits with the change, which is
     * then reported once.
     *
     * @return void
     */
    public function testARevocationThatSucceedsCommitsWithTheChange(): void
    {
        $this->bindRevocation(false);

        $result = $this->turnOn();

        self::assertTrue($result->isChanged());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());

        $stored = TenantEnforcement::query()->sole();

        self::assertTrue($stored->enabled);
        self::assertSame($result->enforcement?->version, $stored->version);
        self::assertSame([[self::TENANT, $stored->version]], $this->revoked());
        $this->assertEventSequence([EnforcementChanged::class]);
    }

    /**
     * A revocation that writes and then throws leaves neither its write nor the
     * change, and nothing is reported; the exception propagates.
     *
     * @return void
     */
    public function testARevocationThatFailsRollsBothBack(): void
    {
        $this->bindRevocation(true);

        try {
            $this->turnOn();
            self::fail('The change succeeded.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The sessions could not be revoked.', $exception->getMessage());
        }

        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertSame(0, TenantEnforcement::query()->count());
        self::assertSame([], $this->revoked());
        $this->assertNoEvents();
    }

    /**
     * A revocation that fails a later change, called once for the connections
     * that change names, leaves the rule as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationThatFailsALaterChangeLeavesTheRule(): void
    {
        $this->bindRevocation(false);

        $first  = $this->turnOn();
        $second = $this->makeConnection(['enabled' => true]);
        $asked  = $this->bindRevocation(true);

        $this->startRecordingEvents();

        try {
            $this->service()->update(self::TENANT, true, [$this->connection->id, $second->id]);
            self::fail('The change succeeded.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The sessions could not be revoked.', $exception->getMessage());
        }

        self::assertCount(1, $asked);
        self::assertEqualsCanonicalizing([$this->connection->id, $second->id], $asked[0]?->policy?->connectionIds);

        $stored = TenantEnforcement::query()->sole();

        self::assertSame($first->enforcement?->version, $stored->version);
        self::assertSame([$this->connection->id], $stored->connection_ids);
        self::assertCount(1, $this->revoked());
        $this->assertNoEvents();
    }

    /**
     * Inside a transaction the application opened, the change and the
     * revocation's write are undone by its rollback, though the helper
     * succeeded, and nothing is reported.
     *
     * @return void
     */
    public function testAnApplicationRollbackUndoesBoth(): void
    {
        $this->bindRevocation(false);

        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        $result = $this->turnOn();

        self::assertTrue($result->isChanged());
        self::assertCount(1, $this->revoked());
        $this->assertNoEvents();

        $database->rollBack();

        self::assertSame(0, TenantEnforcement::query()->count());
        self::assertSame([], $this->revoked());
        $this->assertNoEvents();
    }

    /**
     * Inside a transaction the application opened, the change is reported only
     * once it commits.
     *
     * @return void
     */
    public function testAnApplicationCommitReportsTheChange(): void
    {
        $this->bindRevocation(false);

        DB::connection(StorageConnection::name())->transaction(function (): void {

            self::assertTrue($this->turnOn()->isChanged());

            $this->assertNoEvents();
        });

        self::assertSame(1, TenantEnforcement::query()->count());
        self::assertCount(1, $this->revoked());
        $this->assertEventSequence([EnforcementChanged::class]);
    }

    /**
     * Bind a revocation that records the scope in the revocation's table,
     * through the storage connection, and then throws when asked to. Answers
     * every scope it was called with, kept in memory so a rollback leaves it.
     *
     * @param  bool  $fails
     * @return \ArrayObject<int, \SineMacula\Laravel\Sso\Revocation\RevocationScope>
     */
    private function bindRevocation(bool $fails): \ArrayObject
    {
        /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Revocation\RevocationScope> $asked */
        $asked = new \ArrayObject;

        $this->app?->instance(SessionRevocation::class, new readonly class ($fails, self::REVOKED, $asked) implements SessionRevocation {
            /**
             * Constructor.
             *
             * @param  bool  $fails
             * @param  string  $table
             * @param  \ArrayObject<int, \SineMacula\Laravel\Sso\Revocation\RevocationScope>  $asked
             */
            public function __construct(

                /** Whether it throws once it has written. */
                private bool $fails,

                /** The table it writes to. */
                private string $table,

                /** Every scope it was called with. */
                private \ArrayObject $asked,
            ) {}

            /**
             * Write the tenant and the version revoked for, then fail when told
             * to.
             *
             * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function revoke(RevocationScope $scope): void
            {
                $this->asked->append($scope);

                DB::connection(StorageConnection::name())->table($this->table)->insert(['tenant_id' => $scope->tenantId, 'version' => (string) $scope->policy?->version]);

                if ($this->fails) {
                    throw new \RuntimeException('The sessions could not be revoked.');
                }
            }
        });

        return $asked;
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
     * Each tenant and version the revocation wrote, in order.
     *
     * @return list<array{0: string, 1: string}>
     */
    private function revoked(): array
    {
        $rows = DB::connection(StorageConnection::name())->table(self::REVOKED)->orderBy('id')->get(['tenant_id', 'version'])->all();

        return array_values(array_map(static fn (\stdClass $row): array => [(string) $row->tenant_id, (string) $row->version], $rows));
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
