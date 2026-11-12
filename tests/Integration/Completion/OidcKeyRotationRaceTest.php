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
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Metadata\JwksRefetcher;
use SineMacula\Laravel\Sso\Metadata\TransitionReceipts;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
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
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Integration tests racing a key rotation found by an unknown-`kid` refetch.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwksRefetcher::class)]
#[CoversClass(TransitionReceipts::class)]
#[CoversClass(CompletionPipeline::class)]
final class OidcKeyRotationRaceTest extends TestCase
{
    use UsesConnections;

    /** @var string The tenant of the connection. */
    private const string TENANT = 'tenant-1';

    /** @var string The change that raises the trust version again. */
    private const string TRUST = 'trust';

    /** @var string The change that removes a trusted certificate. */
    private const string DISTRUST = 'distrust';

    /** @var string The change that disables the connection. */
    private const string DISABLE = 'disable';

    /** @var string The change that deletes the connection. */
    private const string DELETE = 'delete';

    /** @var float Seconds a racer waits for the other's signal before it gives up. */
    private const float SIGNAL_SECONDS = 15.0;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The key the provider signs with first, made once. */
    private static ?FakeSigningKey $key = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The key the provider rotates to, made once. */
    private static ?FakeSigningKey $next = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider. */
    private FakeOpenIdProvider $provider;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection signed in through. */
    private Connection $connection; // @phpstan-ignore property.uninitialized

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /**
     * Skip on SQLite or without `pcntl`, and make the keys before any fork.
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

        $clock          = new FixedClock('2026-11-01T09:30:00Z');
        $fetcher        = new FakeFetcher;
        $this->provider = (new FakeOpenIdProvider(FakeOpenIdProvider::ISSUER, self::key(), $clock))->serve($fetcher);

        self::next();

        $this->app?->instance(Clock::class, $clock);
        $this->app?->instance(Fetcher::class, $fetcher);
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

        $this->outcomes = sys_get_temp_dir() . '/oidc-rotation-race-' . bin2hex(random_bytes(8));

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
     * Rows of `[change, in a transaction]`: what commits between the refetch
     * and the locks.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideChanges(): iterable
    {
        foreach ([self::TRUST, self::DISTRUST, self::DISABLE, self::DELETE] as $change) {
            yield "{$change}, plainly" => [$change, false];
            yield "{$change}, in a transaction that read first" => [$change, true];
        }
    }

    /**
     * A change between the refetch and the final locks refuses the trigger.
     *
     * @param  string  $change
     * @param  bool  $inTransaction
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideChanges')]
    public function testAChangeBetweenTheRefetchAndTheLocksRefusesTheTrigger(string $change, bool $inTransaction): void
    {
        $this->connection = $this->makeProviderConnection(true);

        $this->trustCertificate();
        $this->rotate();

        [$request, $grant] = $this->started();

        $read    = "{$this->outcomes}/read";
        $sent    = "{$this->outcomes}/userinfo-sent";
        $changed = "{$this->outcomes}/changed";

        $this->provider->respond('userinfo', static function (FetchRequest $fetch) use ($sent, $changed): FetchResult {
            unset($fetch);

            touch($sent);
            self::await($changed);

            return FakeTokenEndpoint::json(200, ['sub' => FakeOpenIdProvider::SUBJECT]);
        });

        $outcomes = $this->race([
            function () use ($read, $grant): string {
                self::await($read);

                return $this->outcomeOf($this->complete($grant));
            },
            fn (): string => $this->competitor($change, $inTransaction, $read, $sent, $changed),
        ]);

        if ($outcomes[1] === 'serialization') {
            self::assertSame(['completed:-:1', 'serialization'], $outcomes);
            self::assertNull($request->fresh()?->voided_at);

            return;
        }

        self::assertSame([self::refused(), 'changed'], $outcomes);

        if ($change === self::DELETE) {
            self::assertNull($this->connection->fresh());

            return;
        }

        self::assertNotNull($request->fresh()?->voided_at);
        self::assertSame(0, HandoffCode::query()->count());
    }

    /**
     * A sign-in consumed before the rotation is refused at its locks; the
     * trigger completes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnotherSignInConsumedBeforeTheRotationIsRefusedAtItsLocks(): void
    {
        $this->connection = $this->makeProviderConnection(false);

        $this->rotate();

        [$trigger, $triggerGrant] = $this->started();
        [$other, $otherGrant]     = $this->started();

        $otherConsumed = "{$this->outcomes}/other-consumed";
        $triggerDone   = "{$this->outcomes}/trigger-done";

        $this->provider->respond('token', fn (FetchRequest $request): FetchResult => $this->tokenAnswer($request, $otherGrant, $triggerGrant, $otherConsumed, $triggerDone));

        $outcomes = $this->race([
            function () use ($triggerGrant, $otherConsumed, $triggerDone): string {
                self::await($otherConsumed);

                try {
                    return $this->complete($triggerGrant)->status->value;
                } finally {
                    touch($triggerDone);
                }
            },
            fn (): string => $this->complete($otherGrant)->reason->value ?? 'completed',
        ]);

        self::assertSame(['completed', FailureReason::CONNECTION_UNAVAILABLE->value], $outcomes);
        self::assertNull($trigger->fresh()?->voided_at);
        self::assertNotNull($other->fresh()?->voided_at);
        self::assertSame(1, HandoffCode::query()->count());
        self::assertSame(1, $this->connection->fresh()?->trust_version);
    }

    /**
     * Two sign-ins on one unknown `kid` fetch once, and only the claimant
     * completes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTwoTriggersFetchOnceAndOneCompletes(): void
    {
        $this->connection = $this->makeProviderConnection(false);

        $this->rotate();

        [$winner, $winnerGrant] = $this->started();
        [, $loserGrant]         = $this->started();

        $fetching = "{$this->outcomes}/winner-fetching";
        $done     = "{$this->outcomes}/loser-done";

        $this->provider->respond('jwks', function (FetchRequest $request) use ($fetching, $done): FetchResult {
            unset($request);

            touch($fetching);
            self::await($done);

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });

        $outcomes = $this->race([
            fn (): string => $this->complete($winnerGrant)->status->value,
            function () use ($fetching, $done, $loserGrant): string {
                self::await($fetching);

                try {
                    return $this->complete($loserGrant)->reason->value ?? 'completed';
                } finally {
                    touch($done);
                }
            },
        ]);

        self::assertSame(['completed', FailureReason::SIGNATURE_INVALID->value], $outcomes);
        self::assertNull($winner->fresh()?->voided_at);
        self::assertSame(1, HandoffCode::query()->count());
        self::assertSame(1, $this->connection->fresh()?->trust_version);
    }

    /**
     * Answer the trigger at once, and the other sign-in once the trigger
     * finishes.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization  $other
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization  $trigger
     * @param  string  $consumed
     * @param  string  $done
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     */
    private function tokenAnswer(FetchRequest $request, FakeAuthorization $other, FakeAuthorization $trigger, string $consumed, string $done): FetchResult
    {
        $isOther = ($request->form()['code'] ?? null) === $other->code;
        $grant   = $isOther ? $other : $trigger;

        if ($isOther) {
            touch($consumed);
            self::await($done);
        }

        return FakeTokenEndpoint::json(200, ['id_token' => (string) $grant->idToken, 'access_token' => $grant->accessToken, 'token_type' => 'Bearer']);
    }

    /**
     * Make the change once the UserInfo request arrives, plainly or in a
     * transaction that read first.
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
            AuthorizationRequest::query()->where('connection_id', $this->connection->id)->get();
        }

        touch($read);

        try {
            self::await($sent);

            $outcome = $this->isMade($change) ? 'changed' : 'refused';

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
     * Whether the change, made as an administrator, changed the connection.
     *
     * @param  string  $change
     * @return bool
     *
     * @throws \LogicException
     */
    private function isMade(string $change): bool
    {
        $id = $this->connection->id;

        return match ($change) {
            self::TRUST => app(ConnectionService::class)->update(
                self::TENANT,
                $id,
                ['settings' => ['client_secret' => 'the-rotated-client-secret']],
                Clients::browser(),
            )->isChanged(),
            self::DISTRUST => app(KeyService::class)->distrustCertificate(self::TENANT, $id, $this->trustedCertificateId(), Clients::browser())->isSucceeded(),
            self::DISABLE  => app(ConnectionLifecycle::class)->disable(self::TENANT, $id, Clients::browser())->isChanged(),
            self::DELETE   => app(ConnectionLifecycle::class)->delete(self::TENANT, $id, Clients::browser())->isSucceeded(),
            default        => throw new \LogicException(sprintf('No change is named [%s].', $change)),
        };
    }

    /**
     * The id of the connection's trusted certificate.
     *
     * @return string
     */
    private function trustedCertificateId(): string
    {
        return ConnectionKey::query()->where('connection_id', $this->connection->id)->where('use', KeyUse::IDP_SIGNING->value)->sole()->id;
    }

    /**
     * Rotate the provider: the old key gone, the new one published and signing.
     *
     * @return void
     */
    private function rotate(): void
    {
        $this->provider->unpublish('rsa-1')->publish(self::next())->signWith(self::next());
    }

    /**
     * Give the connection a trusted certificate row to distrust.
     *
     * @return void
     */
    private function trustCertificate(): void
    {
        $key = new ConnectionKey;

        $key->forceFill([
            'connection_id' => $this->connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'public_key'    => self::next()->publicKeyPem,
            'fingerprint'   => hash('sha256', self::next()->publicKeyPem),
        ])->save();
    }

    /**
     * Start a sign-in; its request and what the provider granted it.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Models\AuthorizationRequest, 1: \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization}
     *
     * @throws \Random\RandomException
     */
    private function started(): array
    {
        $started = app(AuthorizationRequestService::class)->start('web', Purpose::SIGN_IN, $this->connection->id, Clients::browser());

        self::assertTrue($started->isStarted());

        return [
            AuthorizationRequest::query()->where('reference', (string) $started->reference?->value)->firstOrFail(),
            $this->provider->authorize((string) $started->navigation?->url()),
        ];
    }

    /**
     * Complete at the connection's callback.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization  $grant
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(FakeAuthorization $grant): CompletionResult
    {
        return app(CompletionService::class)->complete(CompletionEndpoint::CALLBACK, $this->connection->id, new CompletionRequest('GET', $grant->query(), []), Clients::browser());
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
     * An enabled connection of the provider storing its key.
     *
     * @param  bool  $userInfo
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function makeProviderConnection(bool $userInfo): Connection
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
                'fetch_userinfo'         => $userInfo,
                'client_id'              => FakeOpenIdProvider::CLIENT_ID,
            ])->toArray(),
        ]);
    }

    /**
     * Fork a process per racer and collect their reports in order.
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
     * Run the racer's work on its own connection and exit without the parent's
     * shutdown.
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
     * What a trigger refused by the change reports.
     *
     * @return string
     */
    private static function refused(): string
    {
        return 'failed:' . FailureReason::CONNECTION_UNAVAILABLE->value . ':0';
    }

    /**
     * Wait up to `SIGNAL_SECONDS` for the signal file, and fail when it never
     * appears.
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
     * Whether the error, or its cause, is a PostgreSQL serialisation failure
     * (SQLSTATE 40001).
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
     * The statement that makes the session's later transactions `REPEATABLE
     * READ`.
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
     * The key the provider signs with first, made once.
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
