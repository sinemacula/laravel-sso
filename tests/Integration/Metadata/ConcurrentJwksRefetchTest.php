<?php

declare(strict_types = 1);

namespace Tests\Integration\Metadata;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\JwksRefreshed;
use SineMacula\Laravel\Sso\Events\JwksRefreshFailed;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Metadata\JwksRefetcher;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\OidcMetadataSource;
use SineMacula\Laravel\Sso\Metadata\ProviderKeys;
use SineMacula\Laravel\Sso\Metadata\RefreshResult;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use SineMacula\Laravel\Sso\Testing\Oidc\JwsSigner;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Protocols\IdentifiedConnection;
use Tests\TestCase;

/**
 * Races a JWKS refetch across processes, each with its own database connection,
 * on PostgreSQL and MySQL (SSO-7.3, SSO-2.13):
 *
 * - two servers hit the same unknown `kid` at once: one claims the cooldown and
 *   fetches. The other, having read the old keys, finds the claim taken once
 *   the winner has written, rereads and finds the key; while the winner still
 *   fetches it finds nothing and refuses;
 * - a refetch paused between its fetch and its write while an administrator
 *   changes the JWKS URI or the client secret: it loses its compare and set and
 *   writes nothing, and the administrator's change stands;
 * - a refetch and a scheduled refresh: exactly one JWKS write wins, and the
 *   other reports `metadata_conflict` and rereads.
 *
 * The order is forced with signal files and a pause before the claim's
 * statement, never with timing. A refetch refuses to run inside a transaction,
 * so it always runs plainly and is shown refusing; the administrator runs
 * plainly, and again inside a `REPEATABLE READ` transaction of its own that
 * read the connection before the refetch claimed it. On PostgreSQL that
 * transaction then fails to serialise (SQLSTATE 40001) when it locks the
 * connection the claim wrote, which leaves the refetch to write: an accepted
 * safe outcome, on PostgreSQL only.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwksRefetcher::class)]
#[CoversClass(ProviderKeys::class)]
#[CoversClass(OidcMetadataSource::class)]
final class ConcurrentJwksRefetchTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var string The tenant the connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var string The issuer the connection is pinned to. */
    private const string ISSUER = FakeOpenIdProvider::ISSUER;

    /** @var string The JWKS URI an administrator moves the connection to. */
    private const string NEW_JWKS_URI = 'https://keys.example.test/jwks';

    /** @var float How long, in seconds, a process waits for another before it gives up. */
    private const float DEADLINE_SECONDS = 30.0;

    /** @var string What a process reports for a serialisation failure. */
    private const string SERIALIZATION_FAILURE = 'serialization_failure';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's key, generated once. */
    private static ?FakeSigningKey $key = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's next key, generated once. */
    private static ?FakeSigningKey $next = null;

    /** @var ?\SineMacula\Laravel\Sso\Models\Connection The connection raced over. */
    private ?Connection $connection = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher every process fetches through. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider, which publishes its next key. */
    private FakeOpenIdProvider $provider;

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database; bind a fixed clock, a
     * fake fetcher serving the provider and a fresh freshness contract; switch
     * OIDC and the refresh on; create the tables, a refreshing connection
     * storing the provider's key, and the directory the processes use.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        $this->fetcher  = new FakeFetcher;
        $this->provider = (new FakeOpenIdProvider(self::ISSUER, self::key()))->publish(self::next())->serve($this->fetcher);

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Fetcher::class, $this->fetcher);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        config()->set('sso.features.oidc', true);
        config()->set('sso.features.metadata_refresh', true);

        $this->createConnectionTables();
        $this->createFlowTables();

        $this->connection = $this->makeConnection(['jwks' => self::stored([self::key()]), 'settings' => OidcSettings::fromArray([
            'issuer'                 => self::ISSUER,
            'authorization_endpoint' => self::ISSUER . '/authorize',
            'token_endpoint'         => self::ISSUER . '/token',
            'jwks_uri'               => self::ISSUER . '/jwks',
            'userinfo_endpoint'      => self::ISSUER . '/userinfo',
            'returns_iss'            => true,
            'client_id'              => FakeOpenIdProvider::CLIENT_ID,
            'metadata_refresh'       => true,
        ])->toArray()]);

        $this->outcomes = sys_get_temp_dir() . '/jwks-refetch-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the signals and outcomes and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if (isset($this->outcomes) && is_dir($this->outcomes)) {

            foreach (glob($this->outcomes . '/*') ?: [] as $file) {
                @unlink($file);
            }

            @rmdir($this->outcomes);
        }

        if ($this->connection !== null) {
            $this->dropFlowTables();
            $this->dropConnectionTables();
        }

        parent::tearDown();
    }

    /**
     * Two servers on one unknown `kid`, the second having read the old keys
     * before the first wrote and claiming after: one claim and one fetch, and
     * the second rereads the winner's keys and finds the key.
     *
     * @return void
     */
    public function testTheLoserOfAClaimRereadsTheWinnersKeys(): void
    {
        $fetching = "{$this->outcomes}/winner-fetching";
        $read     = "{$this->outcomes}/loser-read";
        $written  = "{$this->outcomes}/winner-written";

        $this->countingFetches($fetching, $read);

        [$winner, $loser] = $this->inProcesses([
            function () use ($written): array {
                try {
                    return $this->selected();
                } finally {
                    touch($written);
                }
            },
            function () use ($fetching, $read, $written): array {

                self::await($fetching);

                $this->pauseBeforeClaiming($read, $written);

                return $this->selected();
            },
        ]);

        $reported = (string) json_encode([$winner, $loser]);

        self::assertSame(['selection' => 'found', 'events' => [JwksRefreshed::class]], $winner, $reported);
        self::assertSame(['selection' => 'found', 'events' => []], $loser, $reported);
        self::assertCount(1, glob("{$this->outcomes}/fetched-*") ?: [], $reported);
        self::assertSame(1, $this->row()->jwks_version, $reported);
    }

    /**
     * Two servers on one unknown `kid`, the second claiming while the first
     * still fetches: it fetches nothing, finds only the old keys and refuses,
     * and the first's write stands.
     *
     * @return void
     */
    public function testAClaimWhileTheWinnerFetchesFetchesNothing(): void
    {
        $fetching = "{$this->outcomes}/winner-fetching";
        $done     = "{$this->outcomes}/loser-done";

        $this->countingFetches($fetching, $done);

        [$winner, $loser] = $this->inProcesses([
            fn (): array => $this->selected(),
            function () use ($fetching, $done): array {

                self::await($fetching);

                try {
                    return $this->selected();
                } finally {
                    touch($done);
                }
            },
        ]);

        $reported = (string) json_encode([$winner, $loser]);

        self::assertSame(['selection' => 'found', 'events' => [JwksRefreshed::class]], $winner, $reported);
        self::assertSame(['selection' => 'unknown', 'events' => []], $loser, $reported);
        self::assertCount(1, glob("{$this->outcomes}/fetched-*") ?: [], $reported);
        self::assertSame(1, $this->row()->jwks_version, $reported);
    }

    /**
     * A refetch inside a transaction already open, which read the connection,
     * refuses, with nothing claimed or fetched.
     *
     * @return void
     */
    public function testARefetchInsideAnOpenTransactionRefuses(): void
    {
        $this->countingFetches("{$this->outcomes}/unused", null);

        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        Connection::query()->whereKey($this->connectionId())->get();

        try {
            $this->selected();
            self::fail('A refetch ran inside a transaction.');
        } catch (\LogicException $exception) {
            self::assertSame('A JWKS refetch runs outside any transaction on the storage connection, since it fetches before it writes.', $exception->getMessage());
        } finally {
            $database->rollBack();
        }

        self::assertSame([], glob("{$this->outcomes}/fetched-*") ?: []);
        self::assertNull($this->row()->jwks_refetch_at);
    }

    /**
     * Rows of `[change, in transaction]`: what the administrator changes while
     * the refetch is paused, plainly or inside a transaction of its own.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideAdministratorChanges(): iterable
    {
        yield from [
            'the JWKS URI'                           => ['jwks_uri', false],
            'the JWKS URI inside a transaction'      => ['jwks_uri', true],
            'the client secret'                      => ['client_secret', false],
            'the client secret inside a transaction' => ['client_secret', true],
        ];
    }

    /**
     * A refetch paused between its fetch and its write while an administrator
     * changes the connection's trust loses its compare and set and writes
     * nothing, and the administrator's change stands; on PostgreSQL, an
     * administrator inside a transaction older than the refetch's claim fails
     * to serialise instead, changes nothing, and the refetch writes.
     *
     * @param  string  $change
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideAdministratorChanges')]
    public function testARefetchPausedBetweenFetchAndWriteLosesToAnAdministrator(string $change, bool $inTransaction): void
    {
        $read    = "{$this->outcomes}/administrator-read";
        $fetched = "{$this->outcomes}/fetched";
        $changed = "{$this->outcomes}/changed";

        $this->countingFetches($fetched, $changed);

        [$administrator, $refetch] = $this->inProcesses([
            fn (): array => $this->administrator($change, $inTransaction, $read, $fetched, $changed),
            function () use ($read): array {

                self::await($read);

                return $this->selected();
            },
        ]);

        $reported = (string) json_encode([$administrator, $refetch]);
        $row      = $this->row();

        if ($inTransaction && DB::connection()->getDriverName() === 'pgsql') {
            self::assertSame(self::SERIALIZATION_FAILURE, $administrator['status'] ?? null, $reported);
            self::assertSame(['selection' => 'found', 'events' => [JwksRefreshed::class]], $refetch, $reported);
            self::assertSame([1, 0, self::stored([self::key(), self::next()])], [$row->jwks_version, $row->trust_version, $row->jwks], $reported);
            self::assertSame(self::ISSUER . '/jwks', $row->settings['jwks_uri'] ?? null, $reported);

            return;
        }

        self::assertSame('updated', $administrator['status'] ?? null, $reported);
        self::assertSame(['selection' => 'overtaken', 'events' => [JwksRefreshFailed::class . ':metadata_conflict']], $refetch, $reported);
        $this->assertTheAdministratorsChangeStands($change, $reported);
    }

    /**
     * A scheduled refresh wins while a refetch fetches: exactly one JWKS write,
     * and the refetch reports `metadata_conflict` and rereads the winner's
     * keys.
     *
     * @return void
     */
    public function testARefreshWinsWhileARefetchFetches(): void
    {
        $fetching = "{$this->outcomes}/refetch-fetching";
        $done     = "{$this->outcomes}/refresh-done";

        [$refetch, $refresh] = $this->inProcesses([
            function () use ($fetching, $done): array {

                $this->pausingTheJwks($fetching, $done);

                return $this->selected();
            },
            function () use ($fetching, $done): array {

                self::await($fetching);

                try {
                    return ['status' => $this->refreshDue()->outcome->value];
                } finally {
                    touch($done);
                }
            },
        ]);

        $reported = (string) json_encode([$refetch, $refresh]);
        $row      = $this->row();

        self::assertSame(['status' => 'refreshed'], $refresh, $reported);
        self::assertSame(['selection' => 'found', 'events' => [JwksRefreshFailed::class . ':metadata_conflict']], $refetch, $reported);
        self::assertSame([1, self::stored([self::key(), self::next()])], [$row->jwks_version, $row->jwks], $reported);
    }

    /**
     * A refetch wins while a scheduled refresh fetches: exactly one JWKS write,
     * and the refresh is a conflict that writes nothing.
     *
     * @return void
     */
    public function testARefetchWinsWhileARefreshFetches(): void
    {
        $fetching = "{$this->outcomes}/refresh-fetching";
        $done     = "{$this->outcomes}/refetch-done";

        [$refresh, $refetch] = $this->inProcesses([
            function () use ($fetching, $done): array {

                $this->pausingTheJwks($fetching, $done);

                $result = $this->refreshDue();

                return ['status' => $result->outcome->value, 'reason' => $result->reason?->value];
            },
            function () use ($fetching, $done): array {

                self::await($fetching);

                try {
                    return $this->selected();
                } finally {
                    touch($done);
                }
            },
        ]);

        $reported = (string) json_encode([$refresh, $refetch]);
        $row      = $this->row();

        self::assertSame(['status' => 'conflict', 'reason' => 'metadata_conflict'], $refresh, $reported);
        self::assertSame(['selection' => 'found', 'events' => [JwksRefreshed::class]], $refetch, $reported);
        self::assertSame([1, 0, self::stored([self::key(), self::next()])], [$row->jwks_version, $row->metadata_version, $row->jwks], $reported);
    }

    /**
     * Wait until the other process has signalled, and fail loudly once the
     * deadline passes without it: the process then reports an error, so a race
     * whose processes ran one after the other never passes as one that
     * overlapped.
     *
     * @param  string  $signal
     * @return void
     *
     * @throws \RuntimeException
     */
    public static function await(string $signal): void
    {
        $deadline = microtime(true) + self::DEADLINE_SECONDS;

        while (!file_exists($signal)) {

            if (microtime(true) > $deadline) {
                throw new \RuntimeException(sprintf('The barrier timed out waiting for [%s].', basename($signal)));
            }

            usleep(5000);
            clearstatcache(true, $signal);
        }
    }

    /**
     * Have the JWKS note each fetch and signal it, then, when given one, wait
     * for the signal before it answers.
     *
     * @param  string  $signal
     * @param  ?string  $await
     * @return void
     */
    private function countingFetches(string $signal, ?string $await): void
    {
        $outcomes = $this->outcomes;

        $this->provider->respond('jwks', function () use ($outcomes, $signal, $await): FetchResult {

            touch("{$outcomes}/fetched-" . getmypid());
            touch($signal);

            if ($await !== null) {
                self::await($await);
            }

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });
    }

    /**
     * Have this process's JWKS signal it is being fetched, then wait for the
     * signal before it answers.
     *
     * @param  string  $signal
     * @param  string  $await
     * @return void
     */
    private function pausingTheJwks(string $signal, string $await): void
    {
        $this->provider->respond('jwks', function () use ($signal, $await): FetchResult {

            touch($signal);
            self::await($await);

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });
    }

    /**
     * Pause this process just before it claims the cooldown, having read the
     * keys: signal, then wait for the signal given.
     *
     * @param  string  $read
     * @param  string  $await
     * @return void
     */
    private function pauseBeforeClaiming(string $read, string $await): void
    {
        $paused = false;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query) use (&$paused, $read, $await): void {

            if ($paused || !str_contains($query, 'jwks_claim_token')) {
                return;
            }

            $paused = true;

            touch($read);
            self::await($await);
        });
    }

    /**
     * In a forked process: inside a `REPEATABLE READ` transaction that read the
     * connection first, or plainly, signal it has read, wait for the refetch to
     * fetch, then make the change and signal once that is done or failed.
     *
     * @param  string  $change
     * @param  bool  $inTransaction
     * @param  string  $read
     * @param  string  $fetched
     * @param  string  $changed
     * @return array<string, mixed>
     *
     * @throws \Throwable
     */
    private function administrator(string $change, bool $inTransaction, string $read, string $fetched, string $changed): array
    {
        $database = DB::connection(StorageConnection::name());
        $id       = $this->connectionId();

        if ($inTransaction) {
            $database->statement(self::repeatableReadStatement($database->getDriverName()));
            $database->beginTransaction();

            Connection::query()->whereKey($id)->get();
        }

        touch($read);
        self::await($fetched);

        $settings = $change === 'jwks_uri' ? ['jwks_uri' => self::NEW_JWKS_URI] : ['client_secret' => 'a-new-secret-value'];

        try {
            $result = app(ConnectionService::class)->update(self::TENANT, $id, ['settings' => $settings]);

            if ($inTransaction) {
                $database->commit();
            }

            return ['status' => $result->status->value];
        } catch (\Throwable $exception) {

            if ($database->transactionLevel() > 0) {
                $database->rollBack();
            }

            if (!self::isSerializationFailure($exception)) {
                throw $exception;
            }

            return ['status' => self::SERIALIZATION_FAILURE];
        } finally {
            touch($changed);
        }
    }

    /**
     * Assert that the administrator's change alone is what the row holds: the
     * JWKS URI moved, and its keys cleared with it, or the keys left as they
     * were.
     *
     * @param  string  $change
     * @param  string  $reported
     * @return void
     */
    private function assertTheAdministratorsChangeStands(string $change, string $reported): void
    {
        $row   = $this->row();
        $moved = $change === 'jwks_uri';

        self::assertSame([$moved ? 1 : 0, 1, $moved ? null : self::stored([self::key()])], [$row->jwks_version, $row->trust_version, $row->jwks], $reported);
        self::assertSame($moved ? self::NEW_JWKS_URI : self::ISSUER . '/jwks', $row->settings['jwks_uri'] ?? null, $reported);
    }

    /**
     * Select the key of the provider's next key's token, and report how it
     * ended and what the refetch reported.
     *
     * @return array{selection: string, events: list<string>}
     *
     * @throws \LogicException
     */
    private function selected(): array
    {
        /** @var \ArrayObject<int, string> $events */
        $events = new \ArrayObject;

        Event::listen(SsoEvent::class, static function (SsoEvent $event) use ($events): void {
            $events->append($event instanceof JwksRefreshFailed ? $event::class . ':' . $event->reason->value : $event::class);
        });

        $selection = app(ProviderKeys::class)->select(new IdentifiedConnection($this->connectionId()), self::token(), AlgorithmAllowList::of(['RS256']));

        return ['selection' => $selection->outcome->value, 'events' => array_values($events->getArrayCopy())];
    }

    /**
     * The result of the one connection due.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \RuntimeException
     */
    private function refreshDue(): RefreshResult
    {
        return app(MetadataRefresher::class)->refreshDue()[0] ?? throw new \RuntimeException('No connection was due.');
    }

    /**
     * The connection as stored now.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function row(): Connection
    {
        return Connection::query()->findOrFail($this->connectionId());
    }

    /**
     * The id of the connection raced over.
     *
     * @return string
     */
    private function connectionId(): string
    {
        return (string) $this->connection?->id;
    }

    /**
     * Fork a process per body, have each run its body on a connection of its
     * own, and collect what each reported, in order.
     *
     * @param  list<\Closure(): array<string, mixed>>  $bodies
     * @return list<array<string, mixed>>
     */
    private function inProcesses(array $bodies): array
    {
        DB::disconnect();

        $pids = [];

        foreach ($bodies as $process => $body) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $body);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        $outcomes = [];

        foreach (array_keys($bodies) as $process) {

            $outcome = json_decode((string) file_get_contents("{$this->outcomes}/{$process}"), true);

            $outcomes[] = is_array($outcome) ? $outcome : ['status' => 'unreadable'];
        }

        return $outcomes;
    }

    /**
     * In a forked process: open a connection of its own, run the body, report
     * what it answered, a PostgreSQL serialisation failure, or the error it
     * threw, and end without running the parent's shutdown.
     *
     * @param  int  $process
     * @param  \Closure(): array<string, mixed>  $body
     * @return never
     */
    private function runInChild(int $process, \Closure $body): never
    {
        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            $outcome = $body();
        } catch (\Throwable $e) {
            $outcome = self::isSerializationFailure($e) ? ['status' => self::SERIALIZATION_FAILURE] : ['status' => 'error', 'reason' => $e::class . ': ' . $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/{$process}", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Whether the error, or one it was thrown for, is PostgreSQL's
     * serialisation failure: SQLSTATE 40001 on PostgreSQL. Inside a caller's
     * transaction, Laravel rethrows it as a `DeadlockException` whose previous
     * error is the query's.
     *
     * @param  \Throwable  $exception
     * @return bool
     */
    private static function isSerializationFailure(\Throwable $exception): bool
    {
        for ($error = $exception; $error !== null; $error = $error->getPrevious()) {
            if ($error instanceof QueryException && (string) $error->getCode() === '40001') {
                return DB::connection()->getDriverName() === 'pgsql';
            }
        }

        return false;
    }

    /**
     * The statement that makes every later transaction of the session
     * `REPEATABLE READ`.
     *
     * @param  string  $driver
     * @return string
     *
     * @throws \LogicException
     */
    private static function repeatableReadStatement(string $driver): string
    {
        return match ($driver) {
            'pgsql' => 'set session characteristics as transaction isolation level repeatable read',
            'mysql' => 'set session transaction isolation level repeatable read',
            default => throw new \LogicException(sprintf('No statement sets the isolation on [%s].', $driver)),
        };
    }

    /**
     * The keys as a connection stores them.
     *
     * @param  list<\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey>  $keys
     * @return string
     */
    private static function stored(array $keys): string
    {
        $jwks = (string) json_encode(['keys' => array_map(static fn (FakeSigningKey $key): array => $key->jwk(), $keys)]);

        return ProviderKeySet::read($jwks, AlgorithmAllowList::of(['RS256']), 65536, 50)?->toStored() ?? '';
    }

    /**
     * A token under the provider's next key's `kid`.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken
     *
     * @throws \LogicException
     */
    private static function token(): CompactToken
    {
        $signed = JwsSigner::sign(['alg' => 'RS256', 'kid' => 'rsa-2'], ['sub' => 'a'], self::next());

        return CompactToken::parse($signed, 16384) ?? throw new \LogicException('The token was refused.');
    }

    /**
     * The provider's key, generated once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(): FakeSigningKey
    {
        return self::$key ??= FakeSigningKey::rsa();
    }

    /**
     * The provider's next key, generated once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function next(): FakeSigningKey
    {
        return self::$next ??= FakeSigningKey::rsa('rsa-2');
    }
}
