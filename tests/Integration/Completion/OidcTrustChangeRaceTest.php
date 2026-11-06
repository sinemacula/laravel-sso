<?php

declare(strict_types = 1);

namespace Tests\Integration\Completion;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\SubjectMigration;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\JwksRefreshFailed;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokenValidator;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Races an OpenID Connect completion against a trust change (SSO-2.13, SSO-7.3,
 * SSO-5.1, SSO-11.5), with the real ID token validation: the connection
 * disabled, its issuer changed through the subject migration, or its client
 * secret rotated while the completion's token, JWKS or UserInfo request is in
 * flight, outside any transaction.
 *
 * With a token or UserInfo request in flight, the token verifies against what
 * was stored and the completion, taking its locks, is refused
 * `connection_unavailable`, with no handoff. With a JWKS request in flight, the
 * refetch finds the connection changed under its compare and set, writes
 * nothing and reports `metadata_conflict`, so the key it fetched is never used:
 * the selection is overtaken and the completion `connection_unavailable`,
 * before the locks, with no handoff. Either way the change voids the request
 * and raises the trust version once.
 *
 * In this process the change runs at the barrier, so the order is exact on
 * every database. Across processes, on MySQL and PostgreSQL, the change runs
 * plainly, and inside a `REPEATABLE READ` transaction of the competitor's own
 * that read before the completion began. On PostgreSQL alone that transaction
 * may fail to serialise (SQLSTATE `40001`), which changes nothing, so the
 * completion then completes. The cross-process races are skipped on SQLite and
 * without `pcntl`. A barrier that times out fails its racer loudly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdTokenValidator::class)]
#[CoversClass(CompletionService::class)]
#[CoversClass(CompletionPipeline::class)]
final class OidcTrustChangeRaceTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The tenant of the connection. */
    private const string TENANT = 'tenant-1';

    /** @var string The issuer the subject migration moves the connection to. */
    private const string NEW_ISSUER = 'https://new-op.example.test';

    /** @var string The stage with the token request in flight. */
    private const string TOKEN = 'token';

    /** @var string The stage with the JWKS request in flight. */
    private const string JWKS = 'jwks';

    /** @var string The stage with the UserInfo request in flight. */
    private const string USERINFO = 'userinfo';

    /** @var string The change that disables the connection. */
    private const string DISABLE = 'disable';

    /** @var string The change that moves the issuer through the subject migration. */
    private const string MIGRATE = 'migrate';

    /** @var string The change that rotates the client secret. */
    private const string ROTATE = 'rotate';

    /** @var float Seconds a racer waits for the other's signal before it gives up. */
    private const float SIGNAL_SECONDS = 15.0;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The key the provider signs with, made once. */
    private static ?FakeSigningKey $key = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The key the provider rotates to, made once. */
    private static ?FakeSigningKey $next = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher every request goes through. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider. */
    private FakeOpenIdProvider $provider;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection signed in through. */
    private Connection $connection; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Models\AuthorizationRequest The request in flight. */
    private AuthorizationRequest $request; // @phpstan-ignore property.uninitialized

    /** @var ?\SineMacula\Laravel\Sso\Models\Link The link a migration removes. */
    private ?Link $link = null;

    /** @var \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization What the provider granted. */
    private FakeAuthorization $grant; // @phpstan-ignore property.uninitialized

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /**
     * Bind a fixed clock, fresh authentication, a limiter that allows every
     * attempt and the fake fetcher, configure the endpoints and the
     * application, create the tables, and make the directory the processes
     * report in. The default handoff store is left in place, so every process
     * counts its codes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $clock          = new FixedClock('2026-11-01T09:30:00Z');
        $this->fetcher  = new FakeFetcher;
        $this->provider = (new FakeOpenIdProvider(FakeOpenIdProvider::ISSUER, self::key(), $clock))->serve($this->fetcher);

        $this->app?->instance(Clock::class, $clock);
        $this->app?->instance(Fetcher::class, $this->fetcher);
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

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->usePackageTables();

        $this->outcomes = sys_get_temp_dir() . '/oidc-trust-race-' . bin2hex(random_bytes(8));

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
     * Rows of `[stage, change]`: what is in flight, and what changes meanwhile.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideRaces(): iterable
    {
        foreach ([self::TOKEN, self::JWKS, self::USERINFO] as $stage) {
            foreach ([self::DISABLE, self::MIGRATE, self::ROTATE] as $change) {
                yield "{$stage} request, {$change}" => [$stage, $change];
            }
        }
    }

    /**
     * In this process: the change committing while the request is in flight, in
     * no transaction, refuses the completion with no handoff, voids the request
     * and raises the trust version once, reporting one `FlowFailed`.
     *
     * @param  string  $stage
     * @param  string  $change
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideRaces')]
    public function testAChangeWhileARequestIsInFlightRefusesTheCompletion(string $stage, string $change): void
    {
        $this->arrange($stage, $change);

        $version = (int) $this->connection->fresh()?->trust_version;

        $this->atTheSlowStep($stage, function () use ($change): void {
            self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel(), 'A provider call runs outside any transaction.');
            self::assertTrue($this->hasChanged($change));
        });

        $this->startRecordingEvents();

        self::assertSame(self::refused(), $this->outcomeOf($this->complete()));

        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::CONNECTION_UNAVAILABLE);
        $this->assertVoided();
        self::assertSame($version + 1, $this->connection->fresh()?->trust_version);
    }

    /**
     * Rows of `[change]`: what changes meanwhile.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideChanges(): iterable
    {
        foreach ([self::DISABLE, self::MIGRATE, self::ROTATE] as $change) {
            yield $change => [$change];
        }
    }

    /**
     * A refetch that loses to the change reports `metadata_conflict`, and the
     * key it fetched is never stored.
     *
     * @param  string  $change
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideChanges')]
    public function testARefetchThatLosesToTheChangeKeepsNoKey(string $change): void
    {
        $this->arrange(self::JWKS, $change);

        $this->atTheSlowStep(self::JWKS, function () use ($change): void {
            self::assertTrue($this->hasChanged($change));
        });

        $this->startRecordingEvents();

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->complete()->reason);

        $failures = array_values(array_filter($this->recordedEvents(), static fn (object $event): bool => $event instanceof JwksRefreshFailed));

        self::assertCount(1, $failures);
        self::assertSame(FailureReason::METADATA_CONFLICT, $failures[0]->reason);
        self::assertStringNotContainsString(self::next()->kid ?? '', (string) $this->connection->fresh()?->jwks);
    }

    /**
     * Across processes, the change committing while the request is in flight
     * refuses the completion.
     *
     * @param  string  $stage
     * @param  string  $change
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideRaces')]
    public function testAChangeInAnotherProcessRefusesTheCompletion(string $stage, string $change): void
    {
        $this->assertRacedChangeRefuses($stage, $change, false);
    }

    /**
     * The same race, the change inside the competitor's own `REPEATABLE READ`
     * transaction that read the connection and the request before the
     * completion began.
     *
     * @param  string  $stage
     * @param  string  $change
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideRaces')]
    public function testAChangeInsideACompetitorsTransactionRefusesTheCompletion(string $stage, string $change): void
    {
        $this->assertRacedChangeRefuses($stage, $change, true);
    }

    /**
     * Race the completion against the change in another process, plain or in
     * the competitor's own transaction, and assert it was refused with no
     * handoff or, on PostgreSQL only, that the change failed to serialise and
     * the completion completed.
     *
     * @param  string  $stage
     * @param  string  $change
     * @param  bool  $inTransaction
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function assertRacedChangeRefuses(string $stage, string $change, bool $inTransaction): void
    {
        $this->skipWithoutRacingProcesses();
        $this->arrange($stage, $change);

        $read    = "{$this->outcomes}/read";
        $sent    = "{$this->outcomes}/request-sent";
        $changed = "{$this->outcomes}/changed";

        $this->atTheSlowStep($stage, static function () use ($sent, $changed): void {
            touch($sent);
            self::await($changed);
        });

        $outcomes = $this->race([
            function () use ($read): string {
                self::await($read);

                return $this->outcomeOf($this->complete());
            },
            fn (): string => $this->competitor($change, $inTransaction, $read, $sent, $changed),
        ]);

        if ($outcomes[1] === 'serialization') {
            self::assertSame(['completed:-:1', 'serialization'], $outcomes);
            self::assertNull($this->request->fresh()?->voided_at);

            return;
        }

        self::assertSame([self::refused(), 'changed'], $outcomes);
        $this->assertVoided();
    }

    /**
     * In a forked process: inside its own `REPEATABLE READ` transaction that
     * read first, or plainly, signal it has read, wait for the request to be in
     * flight, make the change, commit, and signal that it is done or failed.
     *
     * @param  string  $change
     * @param  bool  $inTransaction
     * @param  string  $read
     * @param  string  $sent
     * @param  string  $changed
     * @return string
     *
     * @throws \Throwable
     */
    private function competitor(string $change, bool $inTransaction, string $read, string $sent, string $changed): string
    {
        $database = DB::connection(StorageConnection::name());

        if ($inTransaction) {
            $database->statement(self::repeatableReadStatement($database->getDriverName()));
            $database->beginTransaction();

            Connection::query()->whereKey($this->connection->id)->get();
            AuthorizationRequest::query()->whereKey($this->request->id)->get();
        }

        touch($read);

        try {
            self::await($sent);

            $outcome = $this->hasChanged($change) ? 'changed' : 'refused';

            if ($inTransaction) {
                $database->commit();
            }

            return $outcome;
        } catch (\Throwable $exception) {

            if ($database->transactionLevel() > 0) {
                $database->rollBack();
            }

            throw $exception;
        } finally {
            touch($changed);
        }
    }

    /**
     * Make the connection, its request and what the provider grants it: signed
     * with a key the connection does not hold when the JWKS request is the one
     * in flight, and with UserInfo fetched when that is. A migration has a link
     * to remove, as a connection that signs people in has.
     *
     * @param  string  $stage
     * @param  string  $change
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function arrange(string $stage, string $change): void
    {
        $this->connection = $this->connectionFor($stage);

        if ($change === self::MIGRATE) {
            $this->link = $this->makeLink($this->connection, FakeOpenIdProvider::SUBJECT, ['issuer' => $this->provider->issuer]);
        }

        if ($stage === self::JWKS) {
            $this->provider->publish(self::next())->signWith(self::next());
        }

        $started = app(AuthorizationRequestService::class)->start('web', Purpose::SIGN_IN, $this->connection->id, Clients::browser());

        self::assertTrue($started->isStarted());

        $this->request = AuthorizationRequest::query()->where('reference', (string) $started->reference?->value)->firstOrFail();
        $this->grant   = $this->provider->authorize((string) $started->navigation?->url());
    }

    /**
     * Have the endpoint of the stage run the closure when its request arrives,
     * then answer as the provider would.
     *
     * @param  string  $stage
     * @param  \Closure(): void  $barrier
     * @return void
     *
     * @throws \LogicException
     */
    private function atTheSlowStep(string $stage, \Closure $barrier): void
    {
        $answer = match ($stage) {
            self::TOKEN    => fn (): array => ['id_token' => (string) $this->grant->idToken, 'access_token' => $this->grant->accessToken, 'token_type' => 'Bearer'],
            self::JWKS     => fn (): array => $this->provider->jwks(),
            self::USERINFO => static fn (): array => ['sub' => FakeOpenIdProvider::SUBJECT],
            default        => throw new \LogicException(sprintf('No endpoint answers the stage [%s].', $stage)),
        };

        $this->provider->respond($stage, static function (FetchRequest $request) use ($barrier, $answer): FetchResult {
            unset($request);

            $barrier();

            return FakeTokenEndpoint::json(200, $answer());
        });
    }

    /**
     * Make the change as an administrator; whether it changed the connection.
     *
     * @param  string  $change
     * @return bool
     *
     * @throws \LogicException
     */
    private function hasChanged(string $change): bool
    {
        $id = $this->connection->id;

        $result = match ($change) {
            self::DISABLE => app(ConnectionLifecycle::class)->disable(self::TENANT, $id, Clients::browser()),
            self::MIGRATE => app(SubjectMigration::class)->migrate(
                self::TENANT,
                $id,
                ['settings' => ['issuer' => self::NEW_ISSUER]],
                [],
                [(string) $this->link?->id],
                Clients::browser(),
            ),
            self::ROTATE => app(ConnectionService::class)->update(self::TENANT, $id, ['settings' => ['client_secret' => 'the-rotated-client-secret']], Clients::browser()),
            default      => throw new \LogicException(sprintf('No change is named [%s].', $change)),
        };

        return $result->isChanged();
    }

    /**
     * Complete at the connection's callback.
     *
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(): CompletionResult
    {
        return app(CompletionService::class)->complete(
            CompletionEndpoint::CALLBACK,
            $this->connection->id,
            new CompletionRequest('GET', $this->grant->query(), []),
            Clients::browser(),
        );
    }

    /**
     * How the completion ended, and how many codes it left stored.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @return string
     */
    private function outcomeOf(CompletionResult $result): string
    {
        return sprintf('%s:%s:%d', $result->status->value, $result->reason->value ?? '-', HandoffCode::query()->count());
    }

    /**
     * Assert the request was voided, and finished.
     *
     * @return void
     */
    private function assertVoided(): void
    {
        $row = $this->request->fresh();

        self::assertNotNull($row?->voided_at);
        self::assertNotNull($row->consumed_at);
        self::assertNotNull($row->completed_at);
    }

    /**
     * An enabled connection of the provider storing its key, fetching UserInfo
     * when that is the request in flight.
     *
     * @param  string  $stage
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connectionFor(string $stage): Connection
    {
        $jwks = (string) json_encode(['keys' => [self::key()->jwk()]]);

        return $this->makeConnection([
            'tenant_id' => self::TENANT,
            'enabled'   => true,
            'jwks'      => ProviderKeySet::read($jwks, AlgorithmAllowList::of(['RS256']), 65536, 50)?->toStored(),
            'secrets'   => app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret(FakeOpenIdProvider::CLIENT_SECRET)]),
            'settings'  => OidcSettings::fromArray([
                'issuer'                 => $this->provider->issuer,
                'authorization_endpoint' => $this->provider->endpoint('authorization'),
                'token_endpoint'         => $this->provider->endpoint('token'),
                'jwks_uri'               => $this->provider->endpoint('jwks'),
                'userinfo_endpoint'      => $this->provider->endpoint('userinfo'),
                'fetch_userinfo'         => $stage === self::USERINFO,
                'client_id'              => FakeOpenIdProvider::CLIENT_ID,
            ])->toArray(),
        ]);
    }

    /**
     * Skip a race on SQLite or without `pcntl`.
     *
     * @return void
     */
    private function skipWithoutRacingProcesses(): void
    {
        if (DB::connection()->getDriverName() !== 'sqlite' && function_exists('pcntl_fork')) {
            return;
        }

        self::markTestSkipped('Racing processes need a shared database server and pcntl.');
    }

    /**
     * Fork a process for each racer, each on a connection of its own, and
     * collect what each reported, in the racers' order.
     *
     * @param  list<\Closure(): string>  $racers
     * @return list<string>
     */
    private function race(array $racers): array
    {
        DB::disconnect();

        $pids = [];

        foreach ($racers as $process => $work) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $work);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        $outcomes = [];

        foreach (array_keys($racers) as $process) {
            $outcomes[] = (string) file_get_contents("{$this->outcomes}/{$process}");
        }

        return $outcomes;
    }

    /**
     * In a forked process: open a connection of its own, do its work, report
     * the outcome, and end without running the parent's shutdown.
     *
     * @param  int  $process
     * @param  \Closure(): string  $work
     * @return never
     */
    private function runInChild(int $process, \Closure $work): never
    {
        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            $outcome = $work();
        } catch (\Throwable $e) {
            $outcome = self::isSerializationFailure($e) ? 'serialization' : 'error: ' . $e::class . ': ' . $e->getMessage();
        }

        file_put_contents("{$this->outcomes}/{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * What a completion refused with a request in flight reports: its status,
     * its reason and no code.
     *
     * @return string
     */
    private static function refused(): string
    {
        return 'failed:' . FailureReason::CONNECTION_UNAVAILABLE->value . ':0';
    }

    /**
     * Wait for the signal file, for at most `SIGNAL_SECONDS`, and fail loudly
     * when it never appears: the racer then reports an error.
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
     * serialisation failure (SQLSTATE 40001), accepted only there.
     *
     * @param  \Throwable  $exception
     * @return bool
     */
    private static function isSerializationFailure(\Throwable $exception): bool
    {
        for ($error = $exception; $error !== null; $error = $error->getPrevious()) {
            if ((string) $error->getCode() === '40001') {
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
     * The key the provider signs with, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(): FakeSigningKey
    {
        return self::$key ??= FakeSigningKey::rsa('rsa-1');
    }

    /**
     * The key the provider rotates to, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function next(): FakeSigningKey
    {
        return self::$next ??= FakeSigningKey::rsa('rsa-2');
    }
}
