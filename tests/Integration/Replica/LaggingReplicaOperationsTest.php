<?php

declare(strict_types = 1);

namespace Tests\Integration\Replica;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\RecheckEntry;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\ExpiringKey;
use SineMacula\Laravel\Sso\Keys\ExpiryReport;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneKind;
use SineMacula\Laravel\Sso\Pruning\Pruner;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Sso\RateLimiting\RateLimitStore;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use Tests\Concerns\FlowRoutes;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\MakesPrunableRows;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * What runs beside the flows against a lagging replica (SSO-11.3): the rate
 * limit counters, on a lagging pair of their own, where they decide admission;
 * and the candidates `Pruner`, `ExpiryReport`, `DomainRechecker` and
 * `MetadataRefresher` choose, on the write connection: a row missing from the
 * replica is found, one only the replica has is not, and one the primary has
 * moved on is judged as it stands there. A flow served through the two split
 * connections needs neither replica.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAttemptLimiter::class)]
#[CoversClass(RateLimitStore::class)]
#[CoversClass(Pruner::class)]
#[CoversClass(ExpiryReport::class)]
#[CoversClass(DomainRechecker::class)]
#[CoversClass(MetadataRefresher::class)]
final class LaggingReplicaOperationsTest extends TestCase
{
    use FlowRoutes, InteractsWithLaggingReplica, MakesPrunableRows;

    /** @var string The IP address every request and subject counts against. */
    private const string IP = '203.0.113.7';

    /** @var string The tenant of the connections here. */
    private const string TENANT = 'tenant-replica-operations';

    /** @var string A token `makeDomain()` gives a claim. */
    private const string TOKEN = 'abababababababababababababababababababababababababababababababab';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeDnsResolver The resolver a recheck looks records up through. */
    private FakeDnsResolver $dns;

    /**
     * Create the tables on each pair, and the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->prepareFlows();
        $this->migrateSsoTablesOnPrimaryAndReplica();
        $this->registerFlowRoutes();

        $this->dns = new FakeDnsResolver;

        $resolver = $this->dns;

        $this->app?->bind(DnsResolver::class, static fn (): DnsResolver => $resolver);

        config()->set('sso.features.metadata_refresh', true);
    }

    /**
     * Remove the files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->removeLaggingReplicaFiles();

        parent::tearDown();
    }

    /**
     * Counters full on the primary refuse, though the replica's are empty; and
     * they are the limit a start answers.
     *
     * @return void
     */
    public function testACounterFullOnThePrimaryRefusesThoughTheReplicaIsEmpty(): void
    {
        $this->limitStarts(2);

        $connection = $this->flowOidcConnection(self::TENANT, 'op-replica-limits');

        $this->flowStart($connection)->assertOk();
        $this->flowStart($connection)->assertOk();

        self::assertSame(0, DB::connection(self::COUNTERS_REPLICA_CONNECTION)->table($this->counters())->count());

        $this->flowStart($connection)->assertStatus(429);
    }

    /**
     * Counters behind on the replica change nothing: a copy taken after the
     * first attempt says there is room, and the primary's count refuses.
     *
     * @return void
     */
    public function testACounterBehindOnTheReplicaIsNotRead(): void
    {
        $this->limitStarts(2);

        $limiter = app(AttemptLimiter::class);
        $subject = AttemptSubject::authorizationRequest(new ClientContext(self::IP, null));

        self::assertTrue($limiter->attempt($subject)->isAllowed());

        $this->copyEachCounterToReplica();

        self::assertTrue($limiter->attempt($subject)->isAllowed());
        self::assertTrue($limiter->attempt($subject)->isRateLimited());
    }

    /**
     * Counters full on the replica alone refuse nothing: the valid start goes
     * on.
     *
     * @return void
     */
    public function testACounterFullOnTheReplicaAloneRefusesNothing(): void
    {
        $this->limitStarts(1);

        $limiter = app(AttemptLimiter::class);
        $subject = AttemptSubject::authorizationRequest(new ClientContext(self::IP, null));

        self::assertTrue($limiter->attempt($subject)->isAllowed());
        self::assertTrue($limiter->attempt($subject)->isRateLimited());

        $this->copyEachCounterToReplica();

        DB::connection(self::COUNTERS_PRIMARY_CONNECTION)->table($this->counters())->delete();

        $this->flowStart($this->flowOidcConnection(self::TENANT, 'op-replica-limits'))->assertOk();
    }

    /**
     * A flow through the split connections needs neither replica, the counters'
     * included.
     *
     * @return void
     */
    public function testAFlowNeedsNeitherReplica(): void
    {
        $storage = DB::connection(self::REPLICA_CONNECTION)->getSchemaBuilder();

        foreach (array_keys(StorageConnection::TABLES) as $key) {
            $storage->dropIfExists(StorageConnection::table($key));
        }

        DB::connection(self::COUNTERS_REPLICA_CONNECTION)->getSchemaBuilder()->dropIfExists($this->counters());

        self::assertSame(self::TENANT, $this->signedIn($this->flowOidcConnection(self::TENANT, 'op-replica-limits'))['tenant']);
    }

    /**
     * Rows of `[kind]`: every kind a prune deletes.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind}>
     */
    public static function provideKinds(): iterable
    {
        foreach (PruneKind::cases() as $kind) {
            yield $kind->value => [$kind];
        }
    }

    /**
     * An eligible row missing from the replica is found and deleted.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @return void
     */
    #[DataProvider('provideKinds')]
    public function testAPruneFindsARowMissingFromTheReplica(PruneKind $kind): void
    {
        $this->prunableRow($kind, $this->makeConnection(['tenant_id' => self::TENANT]), $this->past());

        $report = app(Pruner::class)->run(true);

        self::assertSame(1, $report->deleted($kind));
        self::assertSame(0, $this->primaryRowsOf($kind));
    }

    /**
     * An eligible row only the replica has is not selected: nothing is counted,
     * and the replica keeps it until it catches up.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @return void
     */
    #[DataProvider('provideKinds')]
    public function testAPruneIgnoresARowOnTheReplicaAlone(PruneKind $kind): void
    {
        $key = $this->prunableRow($kind, $this->makeConnection(['tenant_id' => self::TENANT]), $this->past());

        $this->moveToReplica($kind, $key);

        $report = app(Pruner::class)->run(true);

        self::assertSame(0, $report->deleted($kind));
        self::assertSame(1, $this->replicaRowsOf($kind));
    }

    /**
     * A row eligible on the replica and renewed on the primary stands: a prune
     * judges the row where it writes.
     *
     * @return void
     */
    public function testAPruneJudgesARowAsThePrimaryHasIt(): void
    {
        $connection = $this->makeConnection(['tenant_id' => self::TENANT]);
        $key        = $this->prunableRow(PruneKind::PENDING_CLAIMS, $connection, $this->past());
        $table      = StorageConnection::table('domains.table');

        $this->copyRowToReplica($table, $key);

        DB::connection(self::PRIMARY_CONNECTION)->table($table)->where('id', $key)->update(['pending_expires_at' => '2027-01-01 00:00:00']);

        self::assertSame(0, app(Pruner::class)->run(true)->deleted(PruneKind::PENDING_CLAIMS));
        self::assertSame(1, $this->primaryRowsOf(PruneKind::PENDING_CLAIMS));
    }

    /**
     * An expiring key missing from the replica is listed.
     *
     * @return void
     */
    public function testAnExpiryReportListsAKeyMissingFromTheReplica(): void
    {
        $key = $this->expiringKey($this->makeConnection(['tenant_id' => self::TENANT]));

        self::assertSame([$key->id], $this->listedKeys());
    }

    /**
     * A key only the replica has is not listed, and one the replica says is
     * expiring that the primary has renewed is not either.
     *
     * @return void
     */
    public function testAnExpiryReportIgnoresWhatOnlyTheReplicaSays(): void
    {
        $connection = $this->makeConnection(['tenant_id' => self::TENANT]);
        $table      = StorageConnection::table('keys.table');
        $gone       = $this->expiringKey($connection, 50);
        $renewed    = $this->expiringKey($connection, 51);

        $this->copyRowToReplica($table, $gone->id);
        $this->copyRowToReplica($table, $renewed->id);

        DB::connection(self::PRIMARY_CONNECTION)->table($table)->where('id', $gone->id)->delete();
        DB::connection(self::PRIMARY_CONNECTION)->table($table)->where('id', $renewed->id)->update(['not_after' => '2030-01-01 00:00:00']);

        self::assertSame([], $this->listedKeys());
    }

    /**
     * A verified claim missing from the replica is rechecked.
     *
     * @return void
     */
    public function testARecheckFindsAClaimMissingFromTheReplica(): void
    {
        $connection = $this->makeConnection(['tenant_id' => self::TENANT]);

        $this->flowVerifiedDomain($connection, 'recheck.example.com');
        $this->flowClock->advance(3600);
        $this->dns->found('_sso-verification.recheck.example.com', self::TOKEN);

        self::assertSame(['recheck.example.com'], $this->recheckedDomains());
    }

    /**
     * A claim only the replica has, and one lapsed on the primary that the
     * replica says is verified, are not rechecked.
     *
     * @return void
     */
    public function testARecheckIgnoresWhatOnlyTheReplicaSays(): void
    {
        $connection = $this->makeConnection(['tenant_id' => self::TENANT]);
        $table      = StorageConnection::table('domains.table');
        $gone       = $this->flowVerifiedDomain($connection, 'gone.example.com');
        $lapsed     = $this->flowVerifiedDomain($this->makeConnection(['tenant_id' => self::TENANT]), 'lapsed.example.com');

        $this->copyRowToReplica($table, $gone);
        $this->copyRowToReplica($table, $lapsed);

        DB::connection(self::PRIMARY_CONNECTION)->table($table)->where('id', $gone)->delete();
        DB::connection(self::PRIMARY_CONNECTION)->table($table)->where('id', $lapsed)->update(['state' => DomainState::LAPSED->value]);

        $this->flowClock->advance(3600);

        self::assertSame([], $this->recheckedDomains());
        self::assertSame(DomainState::LAPSED, Domain::query()->useWritePdo()->findOrFail($lapsed)->state);
    }

    /**
     * A connection due on the primary is listed, though it is missing from the
     * replica, or the replica says it is not due.
     *
     * @return void
     */
    public function testARefreshListsWhatThePrimarySaysIsDue(): void
    {
        $table   = StorageConnection::table('connections.table');
        $missing = $this->refreshingConnection();
        $notDue  = $this->refreshingConnection();

        $this->copyRowToReplica($table, $notDue->id);

        DB::connection(self::REPLICA_CONNECTION)->table($table)->where('id', $notDue->id)->update(['metadata_refresh_at' => '2030-01-01 00:00:00']);

        $due = app(MetadataRefresher::class)->dueConnectionIds();

        sort($due);

        $expected = [$missing->id, $notDue->id];

        sort($expected);

        self::assertSame($expected, $due);
    }

    /**
     * A connection the replica alone says is due is not listed: one not due on
     * the primary, and one only the replica has.
     *
     * @return void
     */
    public function testARefreshIgnoresWhatOnlyTheReplicaSaysIsDue(): void
    {
        $table  = StorageConnection::table('connections.table');
        $notDue = $this->refreshingConnection();
        $gone   = $this->refreshingConnection();

        $this->copyRowToReplica($table, $notDue->id);
        $this->copyRowToReplica($table, $gone->id);

        DB::connection(self::PRIMARY_CONNECTION)->table($table)->where('id', $notDue->id)->update(['metadata_refresh_at' => '2030-01-01 00:00:00']);
        DB::connection(self::PRIMARY_CONNECTION)->table($table)->where('id', $gone->id)->delete();

        self::assertSame([], app(MetadataRefresher::class)->dueConnectionIds());
    }

    /**
     * Use the lagging replica, and a lagging pair for the counters.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $this->configureLaggingReplica($config);
        $this->configureLaggingCounters($config);
    }

    /**
     * Allow the starts given per IP address.
     *
     * @param  int  $max
     * @return void
     */
    private function limitStarts(int $max): void
    {
        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => $max, 'decay_seconds' => 60]);
    }

    /**
     * The counters' table.
     *
     * @return string
     */
    private function counters(): string
    {
        return StorageConnection::table('rate_limits.table');
    }

    /**
     * Copy every counter on the counters' primary to its replica.
     *
     * @return void
     */
    private function copyEachCounterToReplica(): void
    {
        foreach (DB::connection(self::COUNTERS_PRIMARY_CONNECTION)->table($this->counters())->pluck('key') as $key) {
            $this->copyRowToReplica($this->counters(), $key, 'key', self::COUNTERS_PRIMARY_CONNECTION, self::COUNTERS_REPLICA_CONNECTION);
        }
    }

    /**
     * An instant well past every retention.
     *
     * @return \Carbon\CarbonImmutable
     */
    private function past(): CarbonImmutable
    {
        return $this->flowClock->now()->subDays(2);
    }

    /**
     * The table of the kind, and the column of its primary key.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @return array{0: string, 1: string}
     */
    private static function tableOf(PruneKind $kind): array
    {
        return match ($kind) {
            PruneKind::AUTHORIZATION_REQUESTS => [StorageConnection::table('authorization_requests.table'), 'id'],
            PruneKind::HANDOFF_CODES          => [StorageConnection::table('handoff_codes.table'), 'id'],
            PruneKind::SINGLE_USE_KEYS        => [StorageConnection::table('single_use.table'), 'id'],
            PruneKind::RESERVATIONS           => [StorageConnection::table('links.table'), 'id'],
            PruneKind::PENDING_CLAIMS         => [StorageConnection::table('domains.table'), 'id'],
            PruneKind::RATE_LIMITS            => [StorageConnection::table('rate_limits.table'), 'key'],
        };
    }

    /**
     * The direct connections of the pair the kind's table lives on: the
     * primary, then the replica.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @return array{0: string, 1: string}
     */
    private static function pairOf(PruneKind $kind): array
    {
        return $kind === PruneKind::RATE_LIMITS
            ? [self::COUNTERS_PRIMARY_CONNECTION, self::COUNTERS_REPLICA_CONNECTION]
            : [self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION];
    }

    /**
     * Move the kind's row from its primary to its replica.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @param  string  $key
     * @return void
     */
    private function moveToReplica(PruneKind $kind, string $key): void
    {
        [$table, $column]    = self::tableOf($kind);
        [$primary, $replica] = self::pairOf($kind);

        $this->copyRowToReplica($table, $key, $column, $primary, $replica);

        DB::connection($primary)->table($table)->where($column, $key)->delete();
    }

    /**
     * How many of the kind's rows its primary holds.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @return int
     */
    private function primaryRowsOf(PruneKind $kind): int
    {
        return DB::connection(self::pairOf($kind)[0])->table(self::tableOf($kind)[0])->count();
    }

    /**
     * How many of the kind's rows its replica holds.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @return int
     */
    private function replicaRowsOf(PruneKind $kind): int
    {
        return DB::connection(self::pairOf($kind)[1])->table(self::tableOf($kind)[0])->count();
    }

    /**
     * A key of the connection that ends tomorrow.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  int  $certificate
     * @return \SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private function expiringKey(Connection $connection, int $certificate = 49): ConnectionKey
    {
        $pem    = Certificates::distinct($certificate);
        $masked = MaskedKey::fromCertificate($pem);
        $key    = new ConnectionKey;

        $key->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::EC,
            'key_bits'      => 256,
            'certificate'   => $pem,
            'public_key'    => (string) $masked->publicKey,
            'fingerprint'   => (string) $masked->fingerprint,
            'not_after'     => $this->flowClock->now()->addDay(),
        ])->save();

        return $key;
    }

    /**
     * The ids an expiry report lists.
     *
     * @return list<string>
     */
    private function listedKeys(): array
    {
        $listed = [];

        app(ExpiryReport::class)->report(Clients::browser(), null, static function (ExpiringKey $entry) use (&$listed): void {
            $listed[] = $entry->key->id;
        });

        return $listed;
    }

    /**
     * The domains a recheck looked at.
     *
     * @return list<string>
     */
    private function recheckedDomains(): array
    {
        return array_map(static fn (RecheckEntry $entry): string => $entry->domain, app(DomainRechecker::class)->recheckAll(Clients::browser())->entries);
    }

    /**
     * A connection that refreshes, due now.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function refreshingConnection(): Connection
    {
        return $this->makeConnection([
            'tenant_id' => self::TENANT,
            'enabled'   => true,
            'settings'  => ['issuer' => 'https://op-replica-refresh.example.test', 'metadata_refresh' => true],
        ]);
    }
}
