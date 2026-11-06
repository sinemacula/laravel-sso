<?php

declare(strict_types = 1);

namespace Tests\Integration\Flows;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Endpoints\ConfiguredEndpointResolver;
use SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\AuthorizationRequests;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Races an OIDC start against a trust change to its connection, an update of
 * its client secret or its JWKS URL through the management helper (SSO-2.13,
 * SSO-5.1, the agreed trust version bullet): a request is either refused or
 * voided, and never survives a change that committed.
 *
 * - The change commits first: the start, held once its driver has read the
 *   callback, outside any transaction, finds the change under the connection's
 *   lock, stores nothing and is refused `connection_unavailable`.
 * - The start commits first: its request is voided by the change, which raises
 *   the trust version.
 *
 * The hold is the endpoint resolver the driver asks, wrapped here, since an
 * OIDC start makes no other call on its way to storing the request. In this
 * process each order is exact on every database. Across processes, on
 * PostgreSQL and MySQL, signal files force the order; the change runs plainly,
 * and inside a `REPEATABLE READ` transaction of its own that read the
 * connection first, which commits after the signal, so the start's locking read
 * waits for it. A start refuses to run inside a transaction, so only the change
 * does. Each barrier fails loudly when its signal never comes.
 *
 * With the start first, a change in a `REPEATABLE READ` transaction that read
 * the connection before the request was stored fails to serialise on PostgreSQL
 * (SQLSTATE 40001, wrapped in a `DeadlockException`), because the stored
 * request raised the connection's flows version: the change commits nothing and
 * the request stays as it was. That outcome is accepted on PostgreSQL only;
 * MySQL's locking reads see the latest rows, so the change commits and voids
 * the request. The cross-process races are skipped on SQLite and without
 * `pcntl`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequests::class)]
#[CoversClass(AuthorizationRequestService::class)]
final class OidcStartRaceTest extends TestCase
{
    use UsesConnections;

    /** @var float Seconds a racer waits for the other's signal before it gives up. */
    private const float SIGNAL_SECONDS = 10.0;

    /** @var string The tenant of the connection. */
    private const string TENANT = 'tenant-1';

    /** @var string The update of the connection's client secret. */
    private const string CLIENT_SECRET = 'client_secret';

    /** @var string The update of the connection's JWKS URL. */
    private const string JWKS_URI = 'jwks_uri';

    /** @var string The value of the client secret the change gives. */
    private const string NEW_SECRET = 'a-rotated-client-secret';

    /** @var string The value of the JWKS URL the change gives. */
    private const string NEW_JWKS_URI = 'https://op.example.test/keys-2';

    /** @var int The trust version of the connection before any change. */
    private const int TRUST_VERSION = 4;

    /** @var string What a process reports for a serialisation failure. */
    private const string SERIALIZATION_FAILURE = 'serialization_failure';

    /** @var string A request neither finished nor voided. */
    private const string OPEN = 'open';

    /** @var string A request voided by a change. */
    private const string VOIDED = 'voided';

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection started through. */
    private Connection $connection;

    /** @var object{onResolve: ?\Closure(): void} The resolver the driver asks, which holds the start. */
    private object $resolver;

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /**
     * Bind a fixed clock, a fresh caller, a limiter that allows every attempt
     * and a resolver that can hold the start; switch OIDC on; register the
     * application and the endpoints; create the tables and a usable connection;
     * and make the directory the processes report in.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://api.example.com');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $this->resolver = new class (new ConfiguredEndpointResolver(config())) implements EndpointResolver {
            /** @var ?\Closure(): void What runs as the endpoints are next asked, once. */
            public ?\Closure $onResolve = null;

            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Endpoints\ConfiguredEndpointResolver  $resolver
             */
            public function __construct(

                /** What answers the endpoints. */
                private readonly ConfiguredEndpointResolver $resolver,
            ) {}

            /**
             * Run what is set to run, once, then answer the endpoints.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints
             */
            #[\Override]
            public function endpoints(SsoConnection $connection): ConnectionEndpoints
            {
                $onResolve       = $this->onResolve;
                $this->onResolve = null;

                if ($onResolve !== null) {
                    $onResolve();
                }

                return $this->resolver->endpoints($connection);
            }
        };

        $this->app?->instance(EndpointResolver::class, $this->resolver);
        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(AttemptLimiter::class, new readonly class implements AttemptLimiter {
            /**
             * Allow every attempt.
             *
             * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject  $subject
             * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptResult
             */
            #[\Override]
            public function attempt(AttemptSubject $subject): AttemptResult
            {
                unset($subject);

                return AttemptResult::allowed();
            }
        });

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'tenant_id'     => self::TENANT,
            'protocol'      => 'oidc',
            'enabled'       => true,
            'trust_version' => self::TRUST_VERSION,
            'secrets'       => app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret('the-client-secret')]),
            'settings'      => [
                'issuer'                 => 'https://op.example.test',
                'authorization_endpoint' => 'https://op.example.test/authorize',
                'token_endpoint'         => 'https://op.example.test/token',
                'jwks_uri'               => 'https://op.example.test/jwks',
                'client_id'              => 'client-1',
            ],
        ]);
        $this->outcomes = sys_get_temp_dir() . '/oidc-start-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove this test's signals and outcomes.
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
     * Rows of `[change]`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideChanges(): iterable
    {
        yield from [
            'a client secret update' => [self::CLIENT_SECRET],
            'a JWKS URL update'      => [self::JWKS_URI],
        ];
    }

    /**
     * A change committed while the start's driver ran refuses the start under
     * the connection's lock: nothing is stored, and the trust version is the
     * change's.
     *
     * @param  string  $change
     * @return void
     */
    #[DataProvider('provideChanges')]
    public function testAChangeWhileTheDriverRanRefusesTheStart(string $change): void
    {
        $this->whenResolved(function () use ($change): void {
            self::assertSame(ConnectionStatus::UPDATED, $this->change($change));
        });

        $result = $this->startFlow();

        self::assertSame([true, FailureReason::CONNECTION_UNAVAILABLE], [$result->isRefused(), $result->reason]);
        self::assertSame(['requests' => [], 'trust_version' => self::TRUST_VERSION + 1, 'changed' => true], $this->rows($change));
    }

    /**
     * A change made once the start committed voids the request it stored, whose
     * trust version is the one the change raised from.
     *
     * @param  string  $change
     * @return void
     */
    #[DataProvider('provideChanges')]
    public function testAChangeAfterTheStartVoidsItsRequest(string $change): void
    {
        self::assertTrue($this->startFlow()->isStarted());
        self::assertSame(self::TRUST_VERSION, AuthorizationRequest::query()->sole()->trust_version);
        self::assertSame(ConnectionStatus::UPDATED, $this->change($change));
        self::assertSame(['requests' => [self::VOIDED], 'trust_version' => self::TRUST_VERSION + 1, 'changed' => true], $this->rows($change));
    }

    /**
     * Rows of `[change, in transaction]`: each change, plainly or inside a
     * transaction of its own that read the connection first.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideRacingChanges(): iterable
    {
        foreach (['a client secret update' => self::CLIENT_SECRET, 'a JWKS URL update' => self::JWKS_URI] as $name => $change) {
            yield "{$name}, plainly" => [$change, false];
            yield "{$name}, inside a transaction" => [$change, true];
        }
    }

    /**
     * Across processes, a change committed while the start is held between its
     * read and its insert refuses the start, which stores nothing, whether the
     * change ran plainly or inside its own transaction.
     *
     * @param  string  $change
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideRacingChanges')]
    public function testAChangeInAnotherProcessRefusesAHeldStart(string $change, bool $inTransaction): void
    {
        self::skipWithoutRacingProcesses();

        $read    = "{$this->outcomes}/read";
        $started = "{$this->outcomes}/started";
        $changed = "{$this->outcomes}/changed";

        [$starter, $changer] = $this->race(
            function () use ($read, $started, $changed): string {
                self::await($read);

                $this->whenResolved(static function () use ($started, $changed): void {
                    touch($started);
                    self::await($changed);
                });

                return self::describe($this->startFlow());
            },
            function () use ($change, $read, $started, $changed): string {
                touch($read);

                try {
                    self::await($started);

                    return $this->change($change)->value;
                } finally {
                    touch($changed);
                }
            },
            $inTransaction,
        );

        self::assertSame(['refused:connection_unavailable', 'updated'], [$starter, $changer]);
        self::assertSame(['requests' => [], 'trust_version' => self::TRUST_VERSION + 1, 'changed' => true], $this->rows($change));
    }

    /**
     * Across processes, a start committed before the change has its request
     * voided by the change. A change inside a transaction that read the
     * connection before the start stored its request fails to serialise on
     * PostgreSQL, changing nothing; no change commits with it left unvoided.
     *
     * @param  string  $change
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideRacingChanges')]
    public function testAStartInAnotherProcessIsVoidedByTheChange(string $change, bool $inTransaction): void
    {
        self::skipWithoutRacingProcesses();

        $read   = "{$this->outcomes}/read";
        $stored = "{$this->outcomes}/stored";

        [$starter, $changer] = $this->race(
            function () use ($read, $stored): string {
                self::await($read);

                try {
                    return self::describe($this->startFlow());
                } finally {
                    touch($stored);
                }
            },
            function () use ($change, $read, $stored): string {
                touch($read);
                self::await($stored);

                return $this->change($change)->value;
            },
            $inTransaction,
        );

        $failed = $inTransaction && DB::connection()->getDriverName() === 'pgsql';

        self::assertSame(['started:-', $failed ? self::SERIALIZATION_FAILURE : 'updated'], [$starter, $changer]);
        self::assertSame($failed
            ? ['requests' => [self::OPEN], 'trust_version' => self::TRUST_VERSION, 'changed' => false]
            : ['requests' => [self::VOIDED], 'trust_version' => self::TRUST_VERSION + 1, 'changed' => true], $this->rows($change));
    }

    /**
     * Skip where processes cannot share the database.
     *
     * @return void
     */
    private static function skipWithoutRacingProcesses(): void
    {
        if (DB::connection()->getDriverName() !== 'sqlite' && function_exists('pcntl_fork')) {
            return;
        }

        self::markTestSkipped('Racing processes need a shared database server and pcntl.');
    }

    /**
     * Have the resolver run the closure as the endpoints are next asked.
     *
     * @param  \Closure(): void  $hold
     * @return void
     */
    private function whenResolved(\Closure $hold): void
    {
        // @phpstan-ignore assign.propertyReadOnly
        $this->resolver->onResolve = $hold;
    }

    /**
     * Start a `sign_in` for `web` through the connection.
     *
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    private function startFlow(): StartResult
    {
        return app(AuthorizationRequestService::class)->start('web', Purpose::SIGN_IN, $this->connection->id, Clients::browser());
    }

    /**
     * Make the change through the management helper.
     *
     * @param  string  $change
     * @return \SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus
     */
    private function change(string $change): ConnectionStatus
    {
        $value = $change === self::CLIENT_SECRET ? self::NEW_SECRET : self::NEW_JWKS_URI;

        return app(ConnectionService::class)->update(self::TENANT, $this->connection->id, ['settings' => [$change => $value]], Clients::browser())->status;
    }

    /**
     * The state of each of the connection's requests, its trust version, and
     * whether the change given reached it.
     *
     * @param  string  $change
     * @return array{requests: list<string>, trust_version: ?int, changed: bool}
     */
    private function rows(string $change): array
    {
        $connection = Connection::query()->useWritePdo()->findOrFail($this->connection->id);
        $changed    = $change                                                                                    === self::CLIENT_SECRET
            ? app(ConnectionSecrets::class)->reveal($connection, self::CLIENT_SECRET)?->equals(self::NEW_SECRET) === true
            : ($connection->settings[self::JWKS_URI] ?? null)                                                    === self::NEW_JWKS_URI;
        $requests = AuthorizationRequest::query()->useWritePdo()->where('connection_id', $connection->id)->orderBy('id')->get()->all();

        return [
            'requests'      => array_values(array_map(static fn (AuthorizationRequest $row): string => $row->voided_at === null ? self::OPEN : self::VOIDED, $requests)),
            'trust_version' => $connection->trust_version,
            'changed'       => $changed,
        ];
    }

    /**
     * What a process reports for a start: its status and its reason.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $result
     * @return string
     */
    private static function describe(StartResult $result): string
    {
        return $result->status->value . ':' . ($result->reason->value ?? '-');
    }

    /**
     * Fork a process for the start and one for the change, have each run on a
     * connection of its own, and collect what each reported.
     *
     * @param  \Closure(): string  $starter
     * @param  \Closure(): string  $changer
     * @param  bool  $inTransaction
     * @return array{0: string, 1: string}
     */
    private function race(\Closure $starter, \Closure $changer, bool $inTransaction): array
    {
        DB::disconnect();

        $pids = [];

        foreach ([[$starter, false], [$changer, $inTransaction]] as $process => [$work, $transaction]) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $work, $transaction);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        return [(string) file_get_contents("{$this->outcomes}/0"), (string) file_get_contents("{$this->outcomes}/1")];
    }

    /**
     * In a forked process: open a connection of its own, do its work, report
     * the outcome, and end without running the parent's shutdown. Racing inside
     * a transaction, the process opens a `REPEATABLE READ` one and reads the
     * connection before its work, and commits after it.
     *
     * @param  int  $process
     * @param  \Closure(): string  $work
     * @param  bool  $inTransaction
     * @return never
     */
    private function runInChild(int $process, \Closure $work, bool $inTransaction): never
    {
        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            $database = DB::connection(StorageConnection::name());

            if ($inTransaction) {
                $database->statement(self::repeatableReadStatement($database->getDriverName()));
                $database->beginTransaction();
                Connection::query()->whereKey($this->connection->id)->get();
            }

            $outcome = $work();

            if ($inTransaction) {
                $database->commit();
            }
        } catch (\Throwable $e) {
            $outcome = self::isSerializationFailure($e) ? self::SERIALIZATION_FAILURE : 'error: ' . $e::class . ': ' . $e->getMessage();
        }

        file_put_contents("{$this->outcomes}/{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Wait for the signal file, for at most `SIGNAL_SECONDS`, and fail loudly
     * when it never appears: the racer then reports an error, so a race whose
     * racers ran one after the other never passes as one that overlapped.
     *
     * @param  string  $signal
     * @return void
     *
     * @throws \RuntimeException
     */
    private static function await(string $signal): void
    {
        $deadline = microtime(true) + self::SIGNAL_SECONDS;

        while (!file_exists($signal)) {

            if (microtime(true) > $deadline) {
                throw new \RuntimeException(sprintf('The barrier timed out waiting for [%s].', basename($signal)));
            }

            usleep(1000);
            clearstatcache(true, $signal);
        }
    }

    /**
     * Whether the error, or one it was thrown for, is PostgreSQL's
     * serialisation failure: SQLSTATE 40001 on PostgreSQL alone. Inside the
     * change's own transaction, Laravel rethrows it as a `DeadlockException`
     * whose previous error is the query's.
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
}
