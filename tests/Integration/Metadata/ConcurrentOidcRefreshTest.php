<?php

declare(strict_types = 1);

namespace Tests\Integration\Metadata;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\OidcMetadataSource;
use SineMacula\Laravel\Sso\Metadata\RefreshResult;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Races a refresh of an OIDC connection's discovery document and JWKS across
 * processes, each with its own database connection, on PostgreSQL and MySQL
 * (SSO-2.8, SSO-2.13, SSO-11.12):
 *
 * - two refreshers of one connection: the claim lets exactly one fetch;
 * - a refresh paused between its fetch and its write while an administrator
 *   changes a setting: a setting the refresh depends on is a conflict, and it
 *   writes nothing, so the administrator's change stands; a setting it neither
 *   depends on nor changes stands beside it;
 * - a refresh whose claim expired while it fetched and was taken over: the one
 *   that lost its claim writes nothing, whether it then applies or records a
 *   failure, and the new owner's refresh stands.
 *
 * The order is forced with signal files, never with timing. A refresh refuses
 * to run inside a transaction, so it always runs plainly; the administrator
 * runs plainly, and again inside a `REPEATABLE READ` transaction of its own
 * that read the connection before the refresh claimed it. On PostgreSQL that
 * transaction then fails to serialise (SQLSTATE 40001) when it locks the
 * connection the claim wrote, which leaves the refresh to apply: an accepted
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
#[CoversClass(OidcMetadataSource::class)]
#[CoversClass(MetadataRefresher::class)]
final class ConcurrentOidcRefreshTest extends TestCase
{
    use UsesConnections;

    /** @var string The tenant the connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var string The issuer the connection is pinned to. */
    private const string ISSUER = FakeOpenIdProvider::ISSUER;

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

        $this->usePackageTables();

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

        $this->outcomes = sys_get_temp_dir() . '/oidc-refresh-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the signals and outcomes.
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

        parent::tearDown();
    }

    /**
     * Two refreshers of one connection: the first claims it and fetches, and
     * the second, running while the first fetches, finds nothing due and
     * fetches nothing.
     *
     * @return void
     */
    public function testExactlyOneOfTwoRefreshersFetches(): void
    {
        $fetching = "{$this->outcomes}/fetching";
        $done     = "{$this->outcomes}/second-done";

        $this->pausingTheJwks($fetching, $done);

        [$first, $second] = $this->inProcesses([
            fn (): array => ['status' => $this->refreshDue()->outcome->value],
            function () use ($fetching, $done): array {

                self::await($fetching);

                try {
                    return ['status' => app(MetadataRefresher::class)->refreshDue(Clients::browser()) === [] ? 'nothing_due' : 'refreshed'];
                } finally {
                    touch($done);
                }
            },
        ]);

        $reported = (string) json_encode([$first, $second]);

        self::assertSame(['status' => 'refreshed'], $first, $reported);
        self::assertSame(['status' => 'nothing_due'], $second, $reported);
        self::assertCount(1, glob("{$this->outcomes}/fetched-*") ?: [], $reported);
        self::assertSame([1, 1], [$this->row()->metadata_version, $this->row()->jwks_version], $reported);
    }

    /**
     * A refresh inside a transaction already open, which read the connection,
     * refuses, with nothing claimed or fetched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshInsideAnOpenTransactionRefuses(): void
    {
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        Connection::query()->whereKey($this->connectionId())->get();

        try {
            app(MetadataRefresher::class)->refreshDue(Clients::browser());
            self::fail('A refresh ran inside a transaction.');
        } catch (\LogicException $exception) {
            self::assertSame('A metadata refresh runs outside any transaction on the storage connection, since it fetches before it writes.', $exception->getMessage());
        } finally {
            $database->rollBack();
        }

        self::assertNull($this->row()->metadata_claim_token);

        $this->fetcher->assertNothingFetched();
    }

    /**
     * Rows of `[settings the administrator changes, in transaction]`, each a
     * trust change the refresh's snapshot holds.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool}>
     */
    public static function provideTrustChanges(): iterable
    {
        $endpoint = ['token_endpoint' => 'https://moved.example.test/token'];
        $fetch    = ['fetch_userinfo' => true];

        yield from [
            'an endpoint moved'                      => [$endpoint, false],
            'an endpoint moved inside a transaction' => [$endpoint, true],
            'UserInfo on'                            => [$fetch, false],
            'UserInfo on inside a transaction'       => [$fetch, true],
        ];
    }

    /**
     * A refresh paused between its fetch and its write while an administrator
     * changes a setting it depends on is `metadata_conflict` and writes
     * nothing, and the change stands; on PostgreSQL, an administrator inside a
     * transaction older than the refresh's claim fails to serialise instead,
     * changes nothing, and the refresh applies.
     *
     * @param  array<string, mixed>  $settings
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideTrustChanges')]
    public function testARefreshPausedBetweenFetchAndWriteLosesToAnAdministrator(array $settings, bool $inTransaction): void
    {
        [$administrator, $refresh, $reported] = $this->raceWithAdministrator($settings, $inTransaction);

        $failed = $inTransaction && DB::connection()->getDriverName() === 'pgsql';
        $row    = $this->row();

        if ($failed) {
            self::assertSame(self::SERIALIZATION_FAILURE, $administrator['status'] ?? null, $reported);
            self::assertSame(['status' => 'refreshed', 'reason' => null], $refresh, $reported);
            self::assertSame([1, 1, 0], [$row->metadata_version, $row->jwks_version, $row->trust_version], $reported);

            return;
        }

        $name = (string) array_key_first($settings);

        self::assertSame('updated', $administrator['status'] ?? null, $reported);
        self::assertSame(['status' => 'conflict', 'reason' => 'metadata_conflict'], $refresh, $reported);
        self::assertSame([0, 0, 1, null], [$row->metadata_version, $row->jwks_version, $row->trust_version, $row->metadata_fetched_at], $reported);
        self::assertSame(self::stored([self::key()]), $row->jwks, $reported);
        self::assertSame($settings[$name], $row->settings[$name] ?? null, $reported);
    }

    /**
     * A change of a setting a refresh neither depends on nor changes raises no
     * trust version and is no conflict: the refresh applies, and the change
     * stands.
     *
     * @return void
     */
    public function testAChangeOfAnotherSettingStandsBesideTheRefresh(): void
    {
        [$administrator, $refresh, $reported] = $this->raceWithAdministrator(['scopes' => ['openid', 'groups']], false);

        $row = $this->row();

        self::assertSame('updated', $administrator['status'] ?? null, $reported);
        self::assertSame(['status' => 'refreshed', 'reason' => null], $refresh, $reported);
        self::assertSame([1, 1, 0], [$row->metadata_version, $row->jwks_version, $row->trust_version], $reported);
        self::assertSame(['openid', 'groups'], $row->settings['scopes'] ?? null, $reported);
    }

    /**
     * Rows of `[served]`: what the refresh whose claim is taken over is served,
     * the JWKS to apply or a failed fetch to record.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideLostClaims(): iterable
    {
        yield from [
            'the stale owner applying'          => [true],
            'the stale owner recording failure' => [false],
        ];
    }

    /**
     * A refresh whose claim expired while it fetched, and was taken over by
     * another server's refresh once it had, writes nothing when it then applies
     * or records a failure: it is `conflict`, and the other refresh's write
     * stands.
     *
     * @param  bool  $served
     * @return void
     */
    #[DataProvider('provideLostClaims')]
    public function testARefreshWhoseClaimWasTakenOverWritesNothing(bool $served): void
    {
        $fetching = "{$this->outcomes}/first-fetching";
        $taken    = "{$this->outcomes}/claim-taken";
        $winner   = FakeTokenEndpoint::json(200, $this->provider->jwks());

        [$stale, $owner] = $this->inProcesses([
            function () use ($fetching, $taken, $served, $winner): array {

                $this->provider->respond('jwks', static function () use ($fetching, $taken, $served, $winner): FetchResult {

                    touch($fetching);
                    self::await($taken);

                    return $served ? $winner : FetchResult::failed();
                });

                $result = $this->refreshDue();

                return ['status' => $result->outcome->value, 'reason' => $result->reason?->value];
            },
            function () use ($fetching, $taken): array {

                self::await($fetching);

                try {
                    app()->instance(Clock::class, new FixedClock('2026-11-01T09:35:01Z'));

                    $result = $this->refreshDue();
                } finally {
                    touch($taken);
                }

                return ['status' => $result->outcome->value, 'reason' => $result->reason?->value];
            },
        ]);

        $reported = (string) json_encode([$stale, $owner]);
        $row      = $this->row();

        self::assertSame(['status' => 'refreshed', 'reason' => null], $owner, $reported);
        self::assertSame(['status' => 'conflict', 'reason' => 'metadata_conflict'], $stale, $reported);
        self::assertSame([1, 1, 0, null, '2026-11-01T09:35:01+00:00'], [
            $row->metadata_version,
            $row->jwks_version,
            $row->metadata_refresh_failures,
            $row->metadata_claim_token,
            $row->metadata_fetched_at?->toIso8601String(),
        ], $reported);
        self::assertSame(self::stored([self::key(), self::next()]), $row->jwks, $reported);
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
     * Race the refresh, paused in its fetch, with the administrator's change.
     *
     * @param  array<string, mixed>  $settings
     * @param  bool  $inTransaction
     * @return array{0: array<string, mixed>, 1: array<string, mixed>, 2: string}
     */
    private function raceWithAdministrator(array $settings, bool $inTransaction): array
    {
        $read    = "{$this->outcomes}/administrator-read";
        $fetched = "{$this->outcomes}/fetched";
        $changed = "{$this->outcomes}/changed";

        $this->pausingTheJwks($fetched, $changed);

        [$administrator, $refresh] = $this->inProcesses([
            fn (): array => $this->administrator($settings, $inTransaction, $read, $fetched, $changed),
            function () use ($read): array {

                self::await($read);

                $result = $this->refreshDue();

                return ['status' => $result->outcome->value, 'reason' => $result->reason?->value];
            },
        ]);

        return [$administrator, $refresh, (string) json_encode([$administrator, $refresh])];
    }

    /**
     * Have the JWKS note each fetch and signal it, then wait for the signal
     * before it answers.
     *
     * @param  string  $signal
     * @param  string  $await
     * @return void
     */
    private function pausingTheJwks(string $signal, string $await): void
    {
        $outcomes = $this->outcomes;

        $this->provider->respond('jwks', function () use ($outcomes, $signal, $await): FetchResult {

            touch("{$outcomes}/fetched-" . getmypid());
            touch($signal);
            self::await($await);

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });
    }

    /**
     * In a forked process: inside a `REPEATABLE READ` transaction that read the
     * connection first, or plainly, signal it has read, wait for the refresh to
     * fetch, then make the change and signal once that is done or failed.
     *
     * @param  array<string, mixed>  $settings
     * @param  bool  $inTransaction
     * @param  string  $read
     * @param  string  $fetched
     * @param  string  $changed
     * @return array<string, mixed>
     *
     * @throws \Throwable
     */
    private function administrator(array $settings, bool $inTransaction, string $read, string $fetched, string $changed): array
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

        try {
            $result = app(ConnectionService::class)->update(self::TENANT, $id, ['settings' => $settings], Clients::browser());

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
     * The result of the one connection due.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \RuntimeException
     */
    private function refreshDue(): RefreshResult
    {
        return app(MetadataRefresher::class)->refreshDue(Clients::browser())[0] ?? throw new \RuntimeException('No connection was due.');
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
