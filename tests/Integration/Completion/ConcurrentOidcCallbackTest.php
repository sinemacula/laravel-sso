<?php

declare(strict_types = 1);

namespace Tests\Integration\Completion;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\CallbackCompletion;
use SineMacula\Laravel\Sso\Protocols\Oidc\ClaimsAssembler;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokenValidator;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\TestCase;

/**
 * Races the OpenID Connect callback (SSO-5.1, SSO-7.2, SSO-2.13), the barrier
 * in the fake token endpoint's closure, so the token request is in flight,
 * outside any transaction, for the whole race:
 *
 * - The same callback submitted twice at once: exactly one consumes the request
 *   and sends exactly one token request, while the other is `request_unknown`.
 * - An administrator rotating the client secret or changing `jwks_uri` while
 *   the token request is in flight voids the request and raises the trust
 *   version, so the completion, taking its locks, is refused
 *   `connection_unavailable` with no handoff.
 *
 * In this process the change runs at the barrier, so the order is exact on
 * every database. Across processes, on MySQL and PostgreSQL, the change runs
 * plainly, and inside the administrator's own already-open `REPEATABLE READ`
 * transaction that read first, and the completion starts only once that read is
 * signalled, so the administrator's snapshot is older than the consumed
 * request. On PostgreSQL that transaction therefore fails to serialise
 * (SQLSTATE `40001`), which changes nothing, so the completion then completes.
 * The cross-process races are skipped on SQLite and without `pcntl`. A barrier
 * that times out fails the racer loudly, so racers that ran one after the other
 * never pass as racers that overlapped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(CallbackCompletion::class)]
final class ConcurrentOidcCallbackTest extends TestCase
{
    use UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var float Seconds a racer waits for the other's signal before it gives up. */
    private const float SIGNAL_SECONDS = 15.0;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The key the provider signs with, made once. */
    private static ?FakeSigningKey $signingKey = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the token request goes through. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider. */
    private FakeOpenIdProvider $provider;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection signed in through. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Models\AuthorizationRequest The request in flight. */
    private AuthorizationRequest $request;

    /** @var \SineMacula\Laravel\Sso\Protocols\CompletionRequest What the browser sends. */
    private CompletionRequest $arrival;

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /** @var int Which racer this process is, in a forked process. */
    private int $racer = 0;

    /**
     * Bind a fixed clock, fresh authentication, a limiter that allows every
     * attempt, the recording issuer, the fake fetcher and the doubles,
     * configure the endpoints and the application, create the tables, the
     * connection, its request and what the browser sends, and make the
     * directory the processes report in.
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
        $this->provider = (new FakeOpenIdProvider(signingKey: self::signingKey(), clock: $clock))->serve($this->fetcher);

        $this->app?->instance(Clock::class, $clock);
        $this->app?->instance(Fetcher::class, $this->fetcher);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(HandoffIssuer::class, new RecordingHandoffIssuer);
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

        $this->bindDoubles();

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->createDomainsTable();
        self::singleUseMigration()->up(); // @phpstan-ignore method.notFound

        $this->connection = $this->makeConnection([
            'enabled'  => true,
            'secrets'  => app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret(FakeOpenIdProvider::CLIENT_SECRET)]),
            'settings' => [
                'issuer'                 => $this->provider->issuer,
                'authorization_endpoint' => $this->provider->endpoint('authorization'),
                'token_endpoint'         => $this->provider->endpoint('token'),
                'jwks_uri'               => $this->provider->endpoint('jwks'),
                'client_id'              => FakeOpenIdProvider::CLIENT_ID,
            ],
        ]);

        $state = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');

        $this->request = $this->makeAuthorizationRequest($this->connection, [
            'state_digest'    => hash('sha256', $state),
            'nonce_digest'    => hash('sha256', 'the-nonce'),
            'code_verifier'   => app(SecretEncrypter::class)->encrypt('the-pkce-verifier-of-the-raced-request-00001'),
            'expected_issuer' => $this->provider->issuer,
        ]);

        $this->arrival  = new CompletionRequest('GET', 'code=the-code&state=' . $state . '&iss=' . rawurlencode($this->provider->issuer), []);
        $this->outcomes = sys_get_temp_dir() . '/oidc-callback-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove this test's signals and outcomes, and drop the tables.
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

        self::singleUseMigration()->down(); // @phpstan-ignore method.notFound
        $this->dropDomainsTable();
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * Rows of `[changes]`: a change an administrator makes that is a trust
     * change.
     *
     * @return iterable<string, array{0: array<string, string>}>
     */
    public static function provideTrustChanges(): iterable
    {
        yield from [
            'rotating the client secret' => [['client_secret' => 'the-rotated-client-secret']],
            'changing the JWKS URL'      => [['jwks_uri' => 'https://op.example.test/other-jwks']],
        ];
    }

    /**
     * In this process: the change committing while the token request is in
     * flight refuses the completion under its lock, with no handoff, and it
     * raises the trust version and voids the request.
     *
     * @param  array<string, string>  $changes
     * @return void
     */
    #[DataProvider('provideTrustChanges')]
    public function testATrustChangeWhileTheTokenRequestIsInFlightRefusesTheCompletion(array $changes): void
    {
        $version = (int) $this->connection->fresh()?->trust_version;

        $this->atTheTokenEndpoint(function () use ($changes): void {
            self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel(), 'The token request runs outside any transaction.');
            self::assertTrue($this->hasChanged($changes));
        });

        self::assertSame('failed:connection_unavailable:1:0', $this->outcomeOf($this->complete()));

        $row = $this->request->fresh();

        self::assertNotNull($row?->voided_at);
        self::assertNotNull($row->completed_at);
        self::assertSame($version + 1, $this->connection->fresh()?->trust_version);
    }

    /**
     * The same callback twice at once: exactly one consumes the request and
     * sends exactly one token request, held open until the other has answered
     * `request_unknown`.
     *
     * @return void
     */
    public function testTheSameCallbackTwiceAtOnceSendsOneTokenRequest(): void
    {
        $this->skipWithoutRacingProcesses();

        $this->atTheTokenEndpoint(function (): void {
            self::await("{$this->outcomes}/done-" . (1 - $this->racer));
        });

        $racer = function (): string {
            $outcome = $this->outcomeOf($this->complete());

            touch("{$this->outcomes}/done-{$this->racer}");

            return $outcome;
        };

        $outcomes = $this->race([[$racer, false], [$racer, false]]);

        sort($outcomes);

        self::assertSame(['completed:-:1:1', 'rejected:request_unknown:0:0'], $outcomes);
        self::assertNotNull($this->request->fresh()?->completed_at);
    }

    /**
     * Across processes, the change committing while the token request is in
     * flight refuses the completion under its lock.
     *
     * @param  array<string, string>  $changes
     * @return void
     */
    #[DataProvider('provideTrustChanges')]
    public function testATrustChangeInAnotherProcessRefusesTheCompletion(array $changes): void
    {
        $this->assertRacedChangeRefuses($changes, false);
    }

    /**
     * The same race, the change inside the administrator's own `REPEATABLE
     * READ` transaction that read the connection and the request before the
     * race began.
     *
     * @param  array<string, string>  $changes
     * @return void
     */
    #[DataProvider('provideTrustChanges')]
    public function testATrustChangeInsideACallersTransactionRefusesTheCompletion(array $changes): void
    {
        $this->assertRacedChangeRefuses($changes, true);
    }

    /**
     * Race the completion against the change in another process, plain or in
     * its own transaction, and assert the completion was refused under the
     * lock, or, in a transaction on PostgreSQL, that the change failed to
     * serialise and the completion completed.
     *
     * @param  array<string, string>  $changes
     * @param  bool  $inTransaction
     * @return void
     */
    private function assertRacedChangeRefuses(array $changes, bool $inTransaction): void
    {
        $this->skipWithoutRacingProcesses();

        $read    = "{$this->outcomes}/read";
        $sent    = "{$this->outcomes}/token-request-sent";
        $changed = "{$this->outcomes}/changed";

        $this->atTheTokenEndpoint(static function () use ($sent, $changed): void {
            touch($sent);
            self::await($changed);
        });

        $outcomes = $this->race([
            [function () use ($read): string {
                self::await($read);

                return $this->outcomeOf($this->complete());
            }, false],
            [function () use ($sent, $changed, $changes): string {
                if (!self::isSignalled($sent)) {
                    return 'error: the token request was never sent';
                }

                try {
                    return $this->hasChanged($changes) ? 'changed' : 'refused';
                } finally {
                    touch($changed);
                }
            }, $inTransaction],
        ]);

        if ($inTransaction && DB::connection()->getDriverName() === 'pgsql') {
            self::assertSame(['completed:-:1:1', 'serialization'], $outcomes);
            self::assertNull($this->request->fresh()?->voided_at);

            return;
        }

        self::assertSame(['failed:connection_unavailable:1:0', 'changed'], $outcomes);

        $row = $this->request->fresh();

        self::assertNotNull($row?->voided_at);
        self::assertNotNull($row->completed_at);
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
     * Have the token endpoint run the closure when a token request arrives,
     * then answer with tokens.
     *
     * @param  \Closure(): void  $barrier
     * @return void
     */
    private function atTheTokenEndpoint(\Closure $barrier): void
    {
        $this->provider->respond('token', static function (FetchRequest $request) use ($barrier): FetchResult {
            unset($request);

            $barrier();

            return FakeTokenEndpoint::json(200, ['id_token' => 'header.payload.signature', 'access_token' => 'the-access-token', 'token_type' => 'Bearer']);
        });
    }

    /**
     * Make the change as an administrator; whether the service made it.
     *
     * @param  array<string, string>  $changes
     * @return bool
     */
    private function hasChanged(array $changes): bool
    {
        return app(ConnectionService::class)->update('tenant-1', $this->connection->id, ['settings' => $changes])->isSucceeded();
    }

    /**
     * Complete at the connection's callback.
     *
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(): CompletionResult
    {
        return app(CompletionService::class)->callback($this->connection->id, $this->arrival);
    }

    /**
     * How the completion ended, how many token requests this process sent, and
     * how many codes it issued.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @return string
     */
    private function outcomeOf(CompletionResult $result): string
    {
        $issuer = app(HandoffIssuer::class);

        assert($issuer instanceof RecordingHandoffIssuer);

        $tokenRequests = array_filter($this->fetcher->requests(), static fn (FetchRequest $request): bool => $request->purpose === FetchPurpose::TOKEN);

        return sprintf('%s:%s:%d:%d', $result->status->value, $result->reason->value ?? '-', count($tokenRequests), count($issuer->grants()));
    }

    /**
     * Fork a process for each racer, have each start its work at the same
     * moment on a connection of its own, plain or inside a transaction of its
     * own, and collect what each reported, in the racers' order.
     *
     * @param  list<array{0: \Closure(): string, 1: bool}>  $racers
     * @return list<string>
     */
    private function race(array $racers): array
    {
        DB::disconnect();

        $start = microtime(true) + 0.5;
        $pids  = [];

        foreach ($racers as $process => [$work, $inTransaction]) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $start, $work, $inTransaction);
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
     * In a forked process: open a connection of its own, signal it has read,
     * wait for its start, do its work, report the outcome, and end without
     * running the parent's shutdown. Racing inside a transaction, the process
     * opens one at `REPEATABLE READ` and reads the connection and the request
     * before it signals, and commits after its work.
     *
     * @param  int  $process
     * @param  float  $start
     * @param  \Closure(): string  $work
     * @param  bool  $inTransaction
     * @return never
     */
    private function runInChild(int $process, float $start, \Closure $work, bool $inTransaction): never
    {
        $this->racer = $process;

        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            $database = DB::connection(StorageConnection::name());

            if ($inTransaction) {
                $database->statement(self::repeatableReadStatement($database->getDriverName()));
                $database->beginTransaction();
                Connection::query()->whereKey($this->connection->id)->get();
                AuthorizationRequest::query()->whereKey($this->request->id)->get();
            }

            touch("{$this->outcomes}/read");

            $wait = $start - microtime(true);

            if ($wait > 0) {
                usleep((int) ($wait * 1000000));
            }

            $outcome = $work();

            if ($inTransaction) {
                $database->commit();
            }
        } catch (\Throwable $e) {
            $outcome = self::isSerializationFailure($e) ? 'serialization' : 'error: ' . $e::class . ': ' . $e->getMessage();
        }

        file_put_contents("{$this->outcomes}/{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * The statement that makes this session's transactions `REPEATABLE READ`,
     * which on PostgreSQL pins the snapshot at the first read.
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
        if (!self::isSignalled($signal)) {
            throw new \RuntimeException(sprintf('The barrier timed out waiting for [%s].', basename($signal)));
        }
    }

    /**
     * Wait for the signal file, for at most `SIGNAL_SECONDS`; whether it
     * appeared.
     *
     * @param  string  $signal
     * @return bool
     */
    private static function isSignalled(string $signal): bool
    {
        $deadline = microtime(true) + self::SIGNAL_SECONDS;

        while (!file_exists($signal)) {

            if (microtime(true) > $deadline) {
                return false;
            }

            usleep(1000);
            clearstatcache(true, $signal);
        }

        return true;
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
     * Bind doubles of the ID token's validation and the claims' assembly, which
     * validate and verify every token.
     *
     * @return void
     */
    private function bindDoubles(): void
    {
        $this->app?->instance(IdTokenValidator::class, new readonly class extends IdTokenValidator {
            /**
             * Constructor: it needs none of what the real validation needs.
             *
             * @phpstan-ignore constructor.missingParentCall
             */
            public function __construct() {}

            /**
             * Validate the token.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
             * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse  $tokens
             * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
             * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation
             */
            #[\Override]
            public function validate(SsoConnection $connection, OidcOptions $options, TokenResponse $tokens, ConsumedRequest $consumed): IdTokenValidation
            {
                unset($connection, $tokens, $consumed);

                return IdTokenValidation::validated(new ValidatedIdToken($options->issuer(), 'the-subject', ['iss' => $options->issuer(), 'sub' => 'the-subject']));
            }
        });

        $this->app?->instance(ClaimsAssembler::class, new readonly class extends ClaimsAssembler {
            /**
             * Constructor: it needs none of what the real assembly needs.
             *
             * @phpstan-ignore constructor.missingParentCall
             */
            public function __construct() {}

            /**
             * Verify the token's issuer and a fixed subject.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
             * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken  $idToken
             * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse  $tokens
             * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
             * @return \SineMacula\Laravel\Sso\Protocols\Completion
             */
            #[\Override]
            public function assemble(SsoConnection $connection, OidcOptions $options, ValidatedIdToken $idToken, TokenResponse $tokens, ConsumedRequest $consumed): Completion
            {
                unset($connection, $options, $tokens, $consumed);

                return Completion::verified(new VerifiedClaims($idToken->issuer, 'the-subject', null, [], new AuthenticationContext));
            }
        });
    }

    /**
     * The key the provider signs with, made once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function signingKey(): FakeSigningKey
    {
        return self::$signingKey ??= FakeSigningKey::rsa();
    }

    /**
     * The shipped migration of the single-use keys.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function singleUseMigration(): Migration
    {
        return require dirname(__DIR__, 3) . self::SINGLE_USE_MIGRATION;
    }
}
