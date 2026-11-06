<?php

declare(strict_types = 1);

namespace Tests\Integration\Domains;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\DomainEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Events\DomainLapsed;
use SineMacula\Laravel\Sso\Events\DomainRecheckFailed;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Integration tests, on a real database, that the domain recheck writes and
 * reports together (SSO-10.5): a recheck run inside a transaction the
 * application opened on the storage connection reports nothing until it
 * commits, and writes (its leases included) and reports nothing when it rolls
 * back, though the run reported what it did.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainRechecker::class)]
#[CoversClass(DomainEvents::class)]
final class DomainRecheckAfterCommitTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesDomains;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeDnsResolver The resolver the recheck looks records up through. */
    private FakeDnsResolver $dns;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection that claimed the domains. */
    private Connection $connection;

    /**
     * Bind a fixed clock and a fake resolver, create the tables and a
     * connection, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');
        $this->dns   = new FakeDnsResolver;

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(DnsResolver::class, $this->dns);

        $this->usePackageTables();

        $this->connection = $this->makeConnection();

        $this->startRecordingEvents();
    }

    /**
     * A suspension inside a transaction that rolls back leaves the claim as it
     * was, unleased, and reports nothing.
     *
     * @return void
     */
    public function testARecheckRolledBackWritesAndReportsNothing(): void
    {
        $claim    = $this->makeDomain($this->connection, 'example.com', ['state' => DomainState::VERIFIED]);
        $database = DB::connection(StorageConnection::name());

        $this->clock->advance(3600);
        $this->dns->absent('_sso-verification.example.com');

        $database->beginTransaction();

        $report = $this->rechecker()->recheckAll();

        $database->rollBack();

        $row = Domain::query()->findOrFail($claim->id);

        self::assertSame(RecheckOutcome::SUSPENDED, $report->entries[0]->outcome);
        self::assertNull($row->linking_suspended_at);
        self::assertNull($row->lapses_at);
        self::assertNull($row->recheck_leased_until);
        $this->assertNoEvents();
    }

    /**
     * A lapse and a suspension inside a transaction that commits report nothing
     * until the commit, then each, in the order the claims were checked.
     *
     * @return void
     */
    public function testARecheckCommittedReportsOnlyAfterTheCommit(): void
    {
        $this->makeDomain($this->connection, 'lapsing.example.com', [
            'state'                    => DomainState::VERIFIED,
            'last_successful_check_at' => CarbonImmutable::parse('2026-10-29T09:30:00Z'),
            'linking_suspended_at'     => CarbonImmutable::parse('2026-10-29T10:30:00Z'),
            'lapses_at'                => CarbonImmutable::parse('2026-11-01T10:00:00Z'),
        ]);

        $this->makeDomain($this->connection, 'absent.example.com', ['state' => DomainState::VERIFIED]);

        $this->clock->advance(3600);
        $this->dns->absent('_sso-verification.absent.example.com');

        $rechecker = $this->rechecker();

        DB::connection(StorageConnection::name())->transaction(function () use ($rechecker): void {

            $report = $rechecker->recheckAll();

            self::assertSame(1, $report->count(RecheckOutcome::LAPSED));
            self::assertSame(1, $report->count(RecheckOutcome::SUSPENDED));

            $this->assertNoEvents();
        });

        $this->assertEventSequence([DomainLapsed::class, DomainRecheckFailed::class]);
    }

    /**
     * The recheck, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Domains\DomainRechecker
     */
    private function rechecker(): DomainRechecker
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DomainRechecker::class);
    }
}
