<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\DomainStanding;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Domains\RecheckReport;
use SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\ExpiryReport;
use SineMacula\Laravel\Sso\Keys\ExpiryRun;
use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneKind;
use SineMacula\Laravel\Sso\Pruning\Pruner;
use SineMacula\Laravel\Sso\Pruning\PruneReport;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Concerns\MakesPrunableRows;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Keys\Certificates;

/**
 * Bounded growth across many rows and connections (SSO-11.11, SSO-11.12), which
 * a small fixed fixture cannot show: each operation is measured at N and at 3N,
 * each budget being its fixed cost plus its documented cost per unit times the
 * units, so the difference is exactly that cost and an N+1 fails it.
 *
 * - The expiry report costs two reads per page, its keys' and its connections',
 *   and one read for the empty page after a full one: nothing per key it has
 *   already notified, however many connections they span. A key warned of costs
 *   two reads and three writes of its own.
 * - The due-connection listing costs one read per chunk and one read of the
 *   anchors for a chunk holding a connection its switch leaves undecided, and
 *   one read for the empty chunk after a full one: nothing per connection.
 * - The domain recheck costs three reads and two writes per claim, one read per
 *   chunk, and one read for the empty chunk after a full one.
 * - Pruning reservations costs one read and two writes per connection in a
 *   batch, one read per page, and one read for the empty page after a full one:
 *   nothing per reservation of a connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExpiryReport::class)]
#[CoversClass(MetadataRefresher::class)]
#[CoversClass(DomainRechecker::class)]
#[CoversClass(Pruner::class)]
#[CoversClass(ReservationWithdrawal::class)]
final class QueryGrowthTest extends PerformanceContractTestCase
{
    use MakesPrunableRows, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var int What the expiry report reads per page: its keys and its connections. */
    private const int READS_PER_REPORT_PAGE = 2;

    /** @var int What a key warned of reads: its connection's lock and its own. */
    private const int READS_PER_WARNED_KEY = 2;

    /** @var int What a key warned of writes: its claim, its marker and its release. */
    private const int WRITES_PER_WARNED_KEY = 3;

    /** @var int What the due-connection listing reads per chunk: the chunk and its anchors. */
    private const int READS_PER_DUE_CHUNK = 2;

    /** @var int What a claim checked reads: its lease's lock, its result's two locks. */
    private const int READS_PER_CLAIM = 3;

    /** @var int What a claim checked writes: its lease and its result. */
    private const int WRITES_PER_CLAIM = 2;

    /** @var int What a connection in a batch of reservations reads: its lock. */
    private const int READS_PER_RESERVING_CONNECTION = 1;

    /** @var int What a connection in a batch of reservations writes: the delete and its links version. */
    private const int WRITES_PER_RESERVING_CONNECTION = 2;

    /** @var int What a run's other kinds read, on the one connection here: one select each. */
    private const int OTHER_KINDS = 5;

    /** @var string The token `makeDomain()` gives a claim. */
    private const string TOKEN = 'abababababababababababababababababababababababababababababababab';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeDnsResolver The resolver a recheck looks records up through. */
    private FakeDnsResolver $dns;

    /**
     * Bind a fake resolver and send the runs' log lines nowhere.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->dns = new FakeDnsResolver;

        $this->app?->instance(DnsResolver::class, $this->dns);

        config()->set('sso.logging.channel', 'null');
    }

    /**
     * Keys already notified cost nothing each, however many connections they
     * span: 10 keys and 30 are one page's two reads.
     *
     * @return void
     */
    public function testNotifiedKeysCostNothingEach(): void
    {
        foreach ([10, 30] as $keys) {
            $this->storeNotifiedKeys($keys, 10);

            $run = $this->assertQueryBudget(self::READS_PER_REPORT_PAGE, 0, fn (): ExpiryRun => $this->reportExpiries());

            self::assertSame($keys, $run->count(ExpiryNotice::ALREADY_NOTIFIED));
        }
    }

    /**
     * Pages cost their two reads each: a page's worth of keys and three are one
     * full page and three, with the one empty page after them.
     *
     * @return void
     */
    public function testExpiryReportPagesGrowByThePage(): void
    {
        foreach ([1, 3] as $pages) {
            $this->storeNotifiedKeys($pages * ExpiryReport::PAGE_SIZE, 20);

            $run = $this->assertQueryBudget(self::READS_PER_REPORT_PAGE * $pages + 1, 0, fn (): ExpiryRun => $this->reportExpiries());

            self::assertSame($pages * ExpiryReport::PAGE_SIZE, $run->listed);
        }
    }

    /**
     * A key warned of, each of its own connection, costs its two reads and
     * three writes and nothing more, beside the page's two reads.
     *
     * @return void
     */
    public function testKeysWarnedOfGrowByTheKey(): void
    {
        foreach ([3, 9] as $keys) {
            $this->storeUnwarnedKeys($keys);

            $reads = self::READS_PER_REPORT_PAGE + self::READS_PER_WARNED_KEY * $keys;

            $writes = self::WRITES_PER_WARNED_KEY * $keys;
            $run    = $this->assertQueryBudget($reads, $writes, fn (): ExpiryRun => $this->reportExpiries());

            self::assertSame($keys, $run->count(ExpiryNotice::NOTIFIED));
        }
    }

    /**
     * The due-connection listing costs nothing per connection: 10 and 30 are
     * one chunk's two reads.
     *
     * @return void
     */
    public function testDueConnectionsCostNothingEach(): void
    {
        foreach ([10, 30] as $connections) {
            $this->storeDueConnections($connections);

            $due = $this->assertQueryBudget(self::READS_PER_DUE_CHUNK, 0, fn (): array => $this->dueConnectionIds());

            self::assertCount($connections, $due);
        }
    }

    /**
     * The due-connection listing costs its two reads per chunk: a chunk's worth
     * of connections and three are one chunk and three, with the one empty
     * chunk after them.
     *
     * @return void
     */
    public function testDueConnectionsGrowByTheChunk(): void
    {
        foreach ([1, 3] as $chunks) {
            $this->storeDueConnections($chunks * MetadataRefresher::CHUNK_SIZE);

            $due = $this->assertQueryBudget(self::READS_PER_DUE_CHUNK * $chunks + 1, 0, fn (): array => $this->dueConnectionIds());

            self::assertCount($chunks * MetadataRefresher::CHUNK_SIZE, $due);
        }
    }

    /**
     * A recheck costs each claim its three reads and two writes and nothing
     * more, beside the chunk's one read, each claim of its own connection.
     *
     * @return void
     */
    public function testRechecksGrowByTheClaim(): void
    {
        foreach ([3, 9] as $claims) {
            $this->storeVerifiedClaims($claims, $claims);

            $reads = 1 + self::READS_PER_CLAIM * $claims;

            $writes = self::WRITES_PER_CLAIM * $claims;
            $report = $this->assertQueryBudget($reads, $writes, fn (): RecheckReport => $this->recheckAll());

            self::assertSame($claims, $report->count(RecheckOutcome::CONFIRMED));
        }
    }

    /**
     * A recheck of a chunk's worth of claims and of three reads one chunk more
     * for each, and the one empty chunk after them.
     *
     * @return void
     */
    public function testRechecksGrowByTheChunk(): void
    {
        foreach ([1, 3] as $chunks) {
            $claims = $chunks * DomainRechecker::CHUNK_SIZE;

            $this->storeVerifiedClaims($claims, 10);

            $reads = $chunks + 1 + self::READS_PER_CLAIM * $claims;

            $writes = self::WRITES_PER_CLAIM * $claims;
            $report = $this->assertQueryBudget($reads, $writes, fn (): RecheckReport => $this->recheckAll());

            self::assertSame($claims, $report->count(RecheckOutcome::CONFIRMED));
        }
    }

    /**
     * Pruning reservations costs each connection in a batch its lock, its
     * delete and its update and nothing more, beside one select of each kind.
     *
     * @return void
     */
    public function testPruningReservationsGrowsByTheConnection(): void
    {
        foreach ([5, 15] as $connections) {
            $this->storeReservations($connections, 1);

            $reads = self::OTHER_KINDS + 1 + self::READS_PER_RESERVING_CONNECTION * $connections;

            $writes = self::WRITES_PER_RESERVING_CONNECTION * $connections;
            $report = $this->assertQueryBudget($reads, $writes, fn (): PruneReport => $this->runPruner());

            self::assertSame($connections, $report->deleted(PruneKind::RESERVATIONS));
        }
    }

    /**
     * Pruning reservations costs nothing per reservation of one connection: 5
     * and 15 in a batch are one lock, one delete and one update.
     *
     * @return void
     */
    public function testPruningReservationsCostsNothingPerReservation(): void
    {
        foreach ([5, 15] as $reservations) {
            $this->storeReservations(1, $reservations);

            $reads  = self::OTHER_KINDS + 1 + self::READS_PER_RESERVING_CONNECTION;
            $report = $this->assertQueryBudget($reads, self::WRITES_PER_RESERVING_CONNECTION, fn (): PruneReport => $this->runPruner());

            self::assertSame($reservations, $report->deleted(PruneKind::RESERVATIONS));
        }
    }

    /**
     * Pruning reservations in batches of five reads one page more for each full
     * batch, and the one empty page after them, beside what each connection
     * costs.
     *
     * @return void
     */
    public function testPruningReservationsGrowsByTheBatch(): void
    {
        config()->set('sso.pruning.batch_size', 5);

        foreach ([1, 3] as $batches) {
            $connections = $batches * 5;

            $this->storeReservations($connections, 1);

            $reads = self::OTHER_KINDS + $batches + 1 + self::READS_PER_RESERVING_CONNECTION * $connections;

            $writes = self::WRITES_PER_RESERVING_CONNECTION * $connections;
            $report = $this->assertQueryBudget($reads, $writes, fn (): PruneReport => $this->runPruner());

            self::assertSame($connections, $report->deleted(PruneKind::RESERVATIONS));
        }
    }

    /**
     * Replace every key with that many of the connections given, each already
     * warned of the threshold it has reached.
     *
     * @param  int  $keys
     * @param  int  $connections
     * @return void
     */
    private function storeNotifiedKeys(int $keys, int $connections): void
    {
        $this->storeKeys($this->freshConnections($connections), $keys, 7);
    }

    /**
     * Replace every key with that many, each of its own connection and warned
     * of nothing.
     *
     * @param  int  $keys
     * @return void
     */
    private function storeUnwarnedKeys(int $keys): void
    {
        $this->storeKeys($this->freshConnections($keys), $keys, null);
    }

    /**
     * Delete every key and connection, and make that many connections.
     *
     * @param  int  $connections
     * @return list<\SineMacula\Laravel\Sso\Models\Connection>
     */
    private function freshConnections(int $connections): array
    {
        return DB::connection()->transaction(function () use ($connections): array {

            ConnectionKey::query()->delete();
            Connection::query()->delete();

            return array_map(fn (int $number): Connection => $this->makeConnection(['tenant_id' => "tenant-{$number}"]), range(1, $connections));
        });
    }

    /**
     * Insert that many certificates ending within a threshold among the
     * connections, in one statement per hundred.
     *
     * @param  list<\SineMacula\Laravel\Sso\Models\Connection>  $connections
     * @param  int  $keys
     * @param  ?int  $notified
     * @return void
     */
    private function storeKeys(array $connections, int $keys, ?int $notified): void
    {
        $model = new ConnectionKey;
        $table = DB::connection()->table($model->getTable());
        $now   = UtcDateTime::format($model, $this->clock->now());
        $ends  = UtcDateTime::format($model, $this->clock->now()->addDays(5));
        $pem   = (string) MaskedKey::fromCertificate(Certificates::rsa2048())->publicKey;

        foreach (array_chunk(range(1, $keys), 100) as $chunk) {
            $table->insert(array_map(static fn (int $number): array => [
                'id'                        => strtolower((string) Str::ulid()),
                'connection_id'             => $connections[$number % count($connections)]->id,
                'use'                       => KeyUse::IDP_SIGNING->value,
                'key_type'                  => KeyType::RSA->value,
                'key_bits'                  => 2048,
                'public_key'                => $pem,
                'fingerprint'               => hash('sha256', "key-{$number}"),
                'not_after'                 => $ends,
                'expiry_notified_threshold' => $notified,
                'created_at'                => $now,
                'updated_at'                => $now,
            ], $chunk));
        }
    }

    /**
     * Run the report.
     *
     * @return \SineMacula\Laravel\Sso\Keys\ExpiryRun
     */
    private function reportExpiries(): ExpiryRun
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ExpiryReport::class)->report();
    }

    /**
     * Replace every connection with that many due SAML connections, whose
     * switch is on or, for every second one, undecided and anchored, so a chunk
     * reads the anchors and every connection is due.
     *
     * @param  int  $connections
     * @return void
     */
    private function storeDueConnections(int $connections): void
    {
        config()->set('sso.features.saml2', true);
        config()->set('sso.features.metadata_refresh', true);

        DB::connection()->transaction(function () use ($connections): void {

            ConnectionKey::query()->delete();
            Connection::query()->delete();

            foreach (range(1, $connections) as $number) {
                $this->storeDueConnection($number);
            }
        });
    }

    /**
     * Make one due SAML connection, undecided and anchored when its number is
     * even and switched on otherwise.
     *
     * @param  int  $number
     * @return void
     */
    private function storeDueConnection(int $number): void
    {
        $settings = [
            'idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID,
            'sso_url'       => FakeSamlIdentityProvider::SSO_URL,
            'metadata_url'  => 'https://idp.example.test/metadata.xml',
        ];

        $undecided  = $number % 2 === 0;
        $connection = $this->makeConnection([
            'protocol'  => 'saml2',
            'tenant_id' => "tenant-{$number}",
            'settings'  => $undecided ? $settings : [...$settings, 'metadata_refresh' => true],
        ]);

        if (!$undecided) {
            return;
        }

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::METADATA_SIGNING,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'public_key'    => 'public-key',
            'fingerprint'   => hash('sha256', "anchor-{$number}"),
        ])->save();
    }

    /**
     * The due connections' ids.
     *
     * @return list<string>
     */
    private function dueConnectionIds(): array
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(MetadataRefresher::class)->dueConnectionIds();
    }

    /**
     * Replace every claim with that many verified claims among that many
     * connections, each last checked a day ago with its record still there, and
     * move the clock on an hour so they are due.
     *
     * @param  int  $claims
     * @param  int  $connections
     * @return void
     */
    private function storeVerifiedClaims(int $claims, int $connections): void
    {
        DB::connection()->transaction(function () use ($claims, $connections): void {

            Domain::query()->delete();
            Connection::query()->delete();

            $owners = array_map(fn (int $number): Connection => $this->makeConnection(['tenant_id' => "tenant-{$number}"]), range(1, $connections));

            foreach (range(1, $claims) as $number) {
                $this->storeVerifiedClaim($owners[$number % $connections], $number);
            }
        });

        $this->clock->advance(3600);
    }

    /**
     * Make the connection's verified claim of a domain of its own, whose record
     * still carries its token.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  int  $number
     * @return void
     */
    private function storeVerifiedClaim(Connection $connection, int $number): void
    {
        $dayAgo = $this->clock->now()->subDay();
        $claim  = $this->makeDomain($connection, "d{$number}.example.com", [
            'state'                    => DomainState::VERIFIED,
            'verified_at'              => $dayAgo,
            'last_successful_check_at' => $dayAgo,
        ]);

        $this->dns->found(DomainStanding::lookupName($claim), self::TOKEN);
    }

    /**
     * Check every verified claim.
     *
     * @return \SineMacula\Laravel\Sso\Domains\RecheckReport
     */
    private function recheckAll(): RecheckReport
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DomainRechecker::class)->recheckAll();
    }

    /**
     * Replace every reservation and connection with that many connections, each
     * with that many expired reservations.
     *
     * @param  int  $connections
     * @param  int  $reservations
     * @return void
     */
    private function storeReservations(int $connections, int $reservations): void
    {
        $past = $this->clock->now()->subDays(2);

        DB::connection()->transaction(function () use ($connections, $reservations, $past): void {

            Link::query()->delete();
            Connection::query()->delete();

            foreach (range(1, $connections) as $number) {

                $connection = $this->makeConnection(['tenant_id' => "tenant-{$number}"]);

                for ($row = 0; $row < $reservations; $row++) {
                    $this->prunableRow(PruneKind::RESERVATIONS, $connection, $past);
                }
            }
        });
    }

    /**
     * Run the pruner.
     *
     * @return \SineMacula\Laravel\Sso\Pruning\PruneReport
     */
    private function runPruner(): PruneReport
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(Pruner::class)->run();
    }
}
