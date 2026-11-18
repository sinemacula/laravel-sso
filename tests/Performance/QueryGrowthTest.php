<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\SubjectMigration;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\DomainStanding;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Domains\RecheckReport;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementLock;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\ExpiryReport;
use SineMacula\Laravel\Sso\Keys\ExpiryRun;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkStore;
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
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Concerns\MakesPrunableRows;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Enforcement\NearestRuleInheritance;
use Tests\Fixtures\Keys\Certificates;

/**
 * Query growth across many rows, connections, links and tenants: each operation
 * is measured at N and 3N, so a cost per unit that is not budgeted fails.
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
#[CoversClass(SubjectMigration::class)]
#[CoversClass(DatabaseEnforcement::class)]
#[CoversClass(EnforcementLock::class)]
#[CoversClass(ScopeWidening::class)]
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

    /** @var int What a relink reads: its connection's lock, its identity's links and its subject's reservation. */
    private const int READS_PER_RELINK = 3;

    /** @var int What a relink writes: its link and its links version. */
    private const int WRITES_PER_RELINK = 2;

    /** @var int What a migration reads beside its relinks: the connection's lock and its links' lock. */
    private const int MIGRATION_READS = 2;

    /** @var int What a migration writes beside its relinks: the settings, the voiding of requests and codes, the trust version and the deletes of reservations and links. */
    private const int MIGRATION_WRITES = 6;

    /** @var int What a tenant in an enforcement path reads under the lock: its rule unlocked, then its row locked, the root's unlocked read giving way to the connections' lock. */
    private const int READS_PER_LOCKED_TENANT = 2;

    /** @var int What a tenant in an enforcement path writes under the lock: its row's upsert. */
    private const int WRITES_PER_LOCKED_TENANT = 1;

    /** @var int What a widening reads, however many identities and links: the rows, the connections' lock and the rows' lock. */
    private const int WIDENING_READS = 3;

    /** @var int What an identity a widening guards writes: its guard. */
    private const int WRITES_PER_GUARD = 1;

    /** @var int What a link a widening suspends writes: its suspension and its connection's links version. */
    private const int WRITES_PER_SUSPENDED_LINK = 2;

    /** @var int What a reservation a widening withdraws writes: its delete. */
    private const int WRITES_PER_WITHDRAWN_RESERVATION = 1;

    /** @var int What a connection a widening withdraws reservations from writes: its links version. */
    private const int WRITES_PER_WITHDRAWING_CONNECTION = 1;

    /** @var string The token `makeDomain()` gives a claim. */
    private const string TOKEN = 'abababababababababababababababababababababababababababababababab';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeDnsResolver The resolver a recheck looks records up through. */
    private FakeDnsResolver $dns;

    /**
     * Bind a fake resolver, a fresh caller and the package's link store, and
     * silence the runs' log.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->dns = new FakeDnsResolver;

        $this->app?->instance(DnsResolver::class, $this->dns);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(Linker::class, app(LinkStore::class));

        config()->set('sso.logging.channel', 'null');
    }

    /**
     * Notified keys cost nothing each, across any connections: 10 and 30 are
     * one page's two reads.
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
     * Pages cost two reads each: one page of keys and three, each with the
     * empty page after.
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
     * three writes, beside the page's two reads.
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
     * The listing costs two reads per chunk: one chunk of connections and
     * three, each with the empty chunk after.
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
     * Each claim, of its own connection, costs three reads and two writes
     * beside the chunk's read.
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
     * One chunk of claims and three read one more per chunk, and the empty
     * chunk after.
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
     * Each connection in a batch costs its lock, delete and update, beside one
     * select of each kind.
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
     * Nothing per reservation of one connection: 5 and 15 in a batch are one
     * lock, one delete and one update.
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
     * Batches of five read one page more per full batch and the empty page
     * after, beside each connection's cost.
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
     * Each relink costs the link's creation, beside the locks and the trust
     * change.
     *
     * @return void
     */
    public function testAMigrationGrowsByTheRelink(): void
    {
        foreach ([3, 9] as $links) {
            [$connection, $ids] = $this->storeMigratingLinks($links);

            $relinks = array_combine($ids, array_map(static fn (string $id): array => ['new-' . $id], $ids));

            $reads  = self::MIGRATION_READS  + self::READS_PER_RELINK  * $links;
            $writes = self::MIGRATION_WRITES + self::WRITES_PER_RELINK * $links;
            $result = $this->assertQueryBudget($reads, $writes, fn (): ConnectionResult => $this->migrate($connection, $relinks, []));

            self::assertSame(ConnectionStatus::MIGRATED, $result->status);
            self::assertEqualsCanonicalizing(array_column($relinks, 0), Link::query()->pluck('subject')->all());
        }
    }

    /**
     * A removal costs nothing each: 3 and 9 are one delete of every link.
     *
     * @return void
     */
    public function testAMigrationCostsNothingPerRemoval(): void
    {
        foreach ([3, 9] as $links) {
            [$connection, $ids] = $this->storeMigratingLinks($links);

            $result = $this->assertQueryBudget(self::MIGRATION_READS, self::MIGRATION_WRITES, fn (): ConnectionResult => $this->migrate($connection, [], $ids));

            self::assertSame(ConnectionStatus::MIGRATED, $result->status);
            self::assertSame(0, Link::query()->count());
        }
    }

    /**
     * Locking a path of tenants to the root's rule costs each tenant its upsert
     * and its locked read, and each below the root its unlocked read, beside
     * the connections' lock; the policy reads each tenant and the connections.
     *
     * @return void
     */
    public function testAnInheritedRuleGrowsByTheTenantInThePath(): void
    {
        config()->set('sso.features.enforcement', true);

        foreach ([3, 9] as $tenants) {
            [$tenant, $root, $connection] = $this->storeTenantPath($tenants);

            $enforcement = app(DatabaseEnforcement::class);
            $lock        = static fn (): EnforcementPolicy => $enforcement->lock($tenant, 'web', [])?->policy() ?? self::fail('The feature is on.');

            $reads  = self::READS_PER_LOCKED_TENANT  * $tenants;
            $writes = self::WRITES_PER_LOCKED_TENANT * $tenants;
            $locked = $this->assertQueryBudget($reads, $writes, static fn (): EnforcementPolicy => DB::connection(StorageConnection::name())->transaction($lock));
            $read   = $this->assertQueryBudget($tenants + 1, 0, static fn (): EnforcementPolicy => $enforcement->policy($tenant, 'web'));

            foreach ([$locked, $read] as $policy) {
                self::assertSame([$root, [$connection]], [$policy->enforcingTenantId, $policy->connectionIds]);
            }
        }
    }

    /**
     * Each identity's guard costs one write and each of its links two, all in
     * one connection, beside the three reads.
     *
     * @return void
     */
    public function testAWideningGrowsByTheIdentity(): void
    {
        foreach ([3, 9] as $identities) {
            $connection = $this->freshConnections(1)[0];
            $people     = array_map(static fn (int $number): IdentityReference => new IdentityReference('App\Models\User', "person-{$number}"), range(1, $identities));

            foreach ($people as $person) {
                $this->storeDomainLink($connection, $person, LinkState::ACTIVE);
            }

            $writes = (self::WRITES_PER_GUARD + self::WRITES_PER_SUSPENDED_LINK) * $identities;

            self::assertSame($identities, $this->assertQueryBudget(self::WIDENING_READS, $writes, fn (): int => $this->widen($people)));
            self::assertSame($identities, Link::query()->where('state', LinkState::SUSPENDED->value)->count());
        }
    }

    /**
     * One identity's active link in each connection costs two writes, the lock
     * of the connections being one read however many.
     *
     * @return void
     */
    public function testAWideningGrowsByTheLinkNotTheConnection(): void
    {
        $person = new IdentityReference('App\Models\User', 'person-1');

        foreach ([3, 9] as $connections) {
            foreach ($this->freshConnections($connections) as $connection) {
                $this->storeDomainLink($connection, $person, LinkState::ACTIVE);
            }

            $writes = self::WRITES_PER_GUARD + self::WRITES_PER_SUSPENDED_LINK * $connections;

            self::assertSame($connections, $this->assertQueryBudget(self::WIDENING_READS, $writes, fn (): int => $this->widen([$person])));
            self::assertSame($connections, Link::query()->where('state', LinkState::SUSPENDED->value)->count());
        }
    }

    /**
     * Each identity's reservation in one connection costs its guard and its
     * delete, beside the connection's one links version.
     *
     * @return void
     */
    public function testAWideningGrowsByTheReservationWithdrawn(): void
    {
        foreach ([3, 9] as $identities) {
            $connection = $this->freshConnections(1)[0];
            $people     = array_map(static fn (int $number): IdentityReference => new IdentityReference('App\Models\User', "person-{$number}"), range(1, $identities));

            foreach ($people as $person) {
                $this->storeDomainLink($connection, $person, LinkState::RESERVED);
            }

            $writes = (self::WRITES_PER_GUARD + self::WRITES_PER_WITHDRAWN_RESERVATION) * $identities + self::WRITES_PER_WITHDRAWING_CONNECTION;

            self::assertSame(0, $this->assertQueryBudget(self::WIDENING_READS, $writes, fn (): int => $this->widen($people)));
            self::assertSame(0, Link::query()->count());
        }
    }

    /**
     * Replace every key with that many across the connections, each warned of
     * the threshold it has reached.
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
     * Delete every key, link and connection, and make that many connections,
     * each of its own tenant and with the attributes.
     *
     * @param  int  $connections
     * @param  array<string, mixed>  $attributes
     * @return list<\SineMacula\Laravel\Sso\Models\Connection>
     */
    private function freshConnections(int $connections, array $attributes = []): array
    {
        return DB::connection()->transaction(function () use ($connections, $attributes): array {

            ConnectionKey::query()->delete();
            Link::query()->delete();
            Connection::query()->delete();

            return array_map(fn (int $number): Connection => $this->makeConnection(['tenant_id' => "tenant-{$number}", ...$attributes]), range(1, $connections));
        });
    }

    /**
     * Insert that many certificates ending within a threshold among the
     * connections, a hundred per statement.
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

        return $app->make(ExpiryReport::class)->report(Clients::browser());
    }

    /**
     * Replace every connection with that many due SAML connections, every
     * second one undecided and anchored so a chunk reads the anchors.
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
     * even.
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
     * Replace every claim with that many verified across the connections,
     * checked a day ago, and move the clock an hour on so they are due.
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
     * Make the connection's verified claim of its own domain, its record still
     * carrying the token.
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

        return $app->make(DomainRechecker::class)->recheckAll(Clients::browser());
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

    /**
     * Replace every link and connection with one OIDC connection holding that
     * many links, each of its own identity; answer it and their ids.
     *
     * @param  int  $links
     * @return array{0: \SineMacula\Laravel\Sso\Models\Connection, 1: list<string>}
     */
    private function storeMigratingLinks(int $links): array
    {
        config()->set('sso.features.oidc', true);

        $connection = $this->freshConnections(1, ['settings' => [
            'issuer'                 => 'https://idp.example.com',
            'authorization_endpoint' => 'https://idp.example.com/authorize',
            'token_endpoint'         => 'https://idp.example.com/token',
            'jwks_uri'               => 'https://idp.example.com/jwks',
            'client_id'              => 'client-123',
        ]])[0];

        $ids = array_map(fn (int $number): string => $this->makeLink($connection, "subject-{$number}", ['identity_id' => (string) $number])->id, range(1, $links));

        return [$connection, $ids];
    }

    /**
     * Move the connection to another client id, relinking and removing its
     * links.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  array<string, array{0: string}>  $relinks
     * @param  list<string>  $removals
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     */
    private function migrate(Connection $connection, array $relinks, array $removals): ConnectionResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $changes = ['settings' => ['client_id' => 'client-456']];

        return $app->make(SubjectMigration::class)->migrate($connection->tenant_id, $connection->id, $changes, $relinks, $removals, Clients::browser());
    }

    /**
     * Bind a tenant tree whose new path of that many tenants ends at a root
     * with a rule on, naming the root's connection; answer the leaf, the root
     * and the connection's id.
     *
     * @param  int  $tenants
     * @return array{0: string, 1: string, 2: string}
     */
    private function storeTenantPath(int $tenants): array
    {
        $path    = array_map(static fn (int $depth): string => "path-{$tenants}-{$depth}", range(1, $tenants));
        $parents = array_combine(array_slice($path, 0, -1), array_slice($path, 1));
        $root    = $path[$tenants - 1];

        $this->app?->instance(EnforcementInheritance::class, new NearestRuleInheritance($parents));

        $connection = $this->makeConnection(['tenant_id' => $root, 'enabled' => true, 'has_completed_sign_in' => true]);

        self::assertTrue(app(EnforcementService::class)->update($root, true, [$connection->id], Clients::browser())->isChanged());

        return [$path[0], $root, $connection->id];
    }

    /**
     * Store the person's link in the connection, made by a verified domain.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $person
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $state
     * @return void
     */
    private function storeDomainLink(Connection $connection, IdentityReference $person, LinkState $state): void
    {
        $reserved = $state === LinkState::RESERVED;

        $this->makeLink($connection, $person->id, [
            'identity_type'          => $person->type,
            'identity_id'            => $person->id,
            'state'                  => $state,
            'provenance'             => LinkOrigin::VERIFIED_DOMAIN,
            'reservation_id'         => $reserved ? strtolower((string) Str::ulid()) : null,
            'reservation_expires_at' => $reserved ? $this->clock->now()->addHour() : null,
        ]);
    }

    /**
     * Widen the people's scope, sparing no tenant, in a transaction.
     *
     * @param  list<\SineMacula\Laravel\Sso\Identities\IdentityReference>  $people
     * @return int
     */
    private function widen(array $people): int
    {
        return DB::connection(StorageConnection::name())->transaction(static fn (): int => app(ScopeWidening::class)->widened($people, [], Clients::browser()));
    }
}
