<?php

declare(strict_types = 1);

namespace Tests\Integration\Domains;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\DomainEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Events\DomainClaimed;
use SineMacula\Laravel\Sso\Events\DomainRemoved;
use SineMacula\Laravel\Sso\Events\DomainVerified;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Integration tests, on a real database, that the domain helpers write and
 * report together (SSO-10.5): a claim, a verification and a removal made inside
 * a transaction the application opened on the storage connection report nothing
 * until it commits, and write and report nothing when it rolls back, though
 * each helper returned success.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainService::class)]
#[CoversClass(DomainEvents::class)]
final class DomainEventsAfterCommitTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeDnsResolver The resolver the helpers look records up through. */
    private FakeDnsResolver $dns;

    /**
     * Bind a fixed clock, a fresh caller and a fake resolver, create the tables
     * and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->dns = new FakeDnsResolver;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(DnsResolver::class, $this->dns);

        $this->createConnectionTables();
        $this->createDomainsTable();
        $this->createFlowTables();
        self::rateLimitsMigration()->up(); // @phpstan-ignore method.notFound

        $this->startRecordingEvents();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::rateLimitsMigration()->down(); // @phpstan-ignore method.notFound
        $this->dropFlowTables();
        $this->dropDomainsTable();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A claim and its verification inside a transaction that rolls back leave
     * no claim and report nothing.
     *
     * @return void
     */
    public function testAClaimRolledBackWritesAndReportsNothing(): void
    {
        $connection = $this->makeConnection();
        $domains    = $this->domains();
        $database   = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        $claimed = $domains->claim('tenant-1', $connection->id, 'example.com');

        $this->dns->publishes($claimed->domain ?? self::fail('Nothing was claimed.'));

        $verified = $domains->verify('tenant-1', $connection->id, 'example.com');

        $database->rollBack();

        self::assertTrue($claimed->isSucceeded());
        self::assertTrue($verified->isSucceeded());
        self::assertSame(0, Domain::query()->count());
        $this->assertNoEvents();
    }

    /**
     * A claim, a verification and a removal inside a transaction that commits
     * report nothing until the commit, then each, in order.
     *
     * @return void
     */
    public function testChangesCommittedReportOnlyAfterTheCommit(): void
    {
        $connection = $this->makeConnection();
        $domains    = $this->domains();

        DB::connection(StorageConnection::name())->transaction(function () use ($domains, $connection): void {

            $claimed = $domains->claim('tenant-1', $connection->id, 'example.com');

            $this->dns->publishes($claimed->domain ?? self::fail('Nothing was claimed.'));

            $domains->verify('tenant-1', $connection->id, 'example.com');
            $domains->remove('tenant-1', $connection->id, 'example.com');

            $this->assertNoEvents();
        });

        $this->assertEventSequence([DomainClaimed::class, DomainVerified::class, DomainRemoved::class]);
    }

    /**
     * The domain helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Domains\DomainService
     */
    private function domains(): DomainService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DomainService::class);
    }

    /**
     * The shipped migration of the rate limit counters.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function rateLimitsMigration(): Migration
    {
        return require dirname(__DIR__, 3) . self::RATE_LIMITS_MIGRATION;
    }
}
