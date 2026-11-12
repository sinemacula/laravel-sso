<?php

declare(strict_types = 1);

namespace Tests\Integration\Completion;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Completion\ResultBuilder;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Completion\Stages\ValidateResponse;
use SineMacula\Laravel\Sso\Completion\VerifiedDeadlines;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Integration tests racing a SAML completion against a certificate trust
 * change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(AssertionValidator::class)]
final class SamlTrustChangeRaceTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var string The `AuthnRequest` id the request was started with. */
    private const string REQUEST_ID = '_request-trust-race-1';

    /** @var string The `RelayState` the request was started with. */
    private const string RELAY_STATE = 'the-relay-state-of-the-trust-race-request';

    /** @var float Seconds a racer waits for the other's signal before it gives up. */
    private const float SIGNAL_SECONDS = 10.0;

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The SAML connection signed in through. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Models\AuthorizationRequest The request in flight. */
    private AuthorizationRequest $request;

    /** @var string The id of the trusted certificate that signs the responses. */
    private string $signingKeyId;

    /** @var \SineMacula\Laravel\Sso\Protocols\CompletionRequest What the browser posts. */
    private CompletionRequest $post;

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /**
     * Configure SAML and create a connection that trusts the identity provider,
     * with its request and response.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
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

        config()->set('sso.features.saml2', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'protocol' => 'saml2',
            'enabled'  => true,
            'settings' => ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL],
        ]);

        $this->signingKeyId = $this->trust(self::idp()->certificate());
        $this->trust(Certificates::distinct(7));

        $this->request  = $this->makeAuthorizationRequest($this->connection, ['saml_request_id' => self::REQUEST_ID, 'state_digest' => hash('sha256', self::RELAY_STATE)]);
        $this->post     = $this->response();
        $this->outcomes = sys_get_temp_dir() . '/saml-trust-race-' . bin2hex(random_bytes(8));

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
     * Distrusting the signing certificate after validation refuses the
     * completion.
     *
     * @return void
     */
    public function testDistrustingTheSigningCertificateMidFlightRefusesTheCompletion(): void
    {
        $version = (int) $this->connection->fresh()?->trust_version;

        $this->holdAfterValidation(fn (): bool => $this->hasDistrustedTheSigningCertificate());

        $result = $this->complete();

        self::assertSame([true, FailureReason::CONNECTION_UNAVAILABLE], [$result->isFailed(), $result->reason]);
        $this->assertRefusedUnderTheLock();
        self::assertSame($version + 1, $this->connection->fresh()?->trust_version);
    }

    /**
     * Trusting another certificate after validation voids nothing.
     *
     * @return void
     */
    public function testTrustingAnotherCertificateMidFlightVoidsNothing(): void
    {
        $this->holdAfterValidation(fn (): bool => $this->trust(Certificates::distinct(8)) !== '');

        $result = $this->complete();

        self::assertTrue($result->isCompleted());
        self::assertNull($this->request->fresh()?->voided_at);
        self::assertSame(1, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());
    }

    /**
     * A distrust in another process while the completion is held refuses it.
     *
     * @return void
     */
    public function testADistrustInAnotherProcessRefusesTheCompletion(): void
    {
        $this->assertRacedDistrustRefuses(false);
    }

    /**
     * The same race, the distrust inside a `REPEATABLE READ` transaction that
     * read first.
     *
     * @return void
     */
    public function testADistrustInsideACallersTransactionRefusesTheCompletion(): void
    {
        $this->assertRacedDistrustRefuses(true);
    }

    /**
     * Race the completion against a distrust and assert it was refused, or the
     * distrust failed to serialise.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    private function assertRacedDistrustRefuses(bool $inTransaction): void
    {
        if (DB::connection()->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        $read      = "{$this->outcomes}/read";
        $validated = "{$this->outcomes}/validated";
        $changed   = "{$this->outcomes}/changed";

        $outcomes = $this->race([
            [function () use ($read, $validated, $changed): string {
                self::await($read);

                $this->holdAfterValidation(static function () use ($validated, $changed): bool {
                    touch($validated);
                    self::await($changed);

                    return true;
                });

                return $this->outcomeOf($this->complete());
            }, false],
            [function () use ($validated, $changed): string {
                if (!self::isSignalled($validated)) {
                    return 'error: the completion never signalled it validated';
                }

                try {
                    $distrusted = $this->hasDistrustedTheSigningCertificate();
                } finally {
                    touch($changed);
                }

                return $distrusted ? 'distrusted' : 'refused';
            }, $inTransaction],
        ]);

        if ($inTransaction && DB::connection()->getDriverName() === 'pgsql') {
            self::assertSame(['completed:-:1', 'serialization'], $outcomes);
            self::assertNull($this->request->fresh()?->voided_at);

            return;
        }

        self::assertSame(['failed:connection_unavailable:0', 'distrusted'], $outcomes);
        $this->assertRefusedUnderTheLock();
    }

    /**
     * Assert the request was voided and finished, and no assertion recorded.
     *
     * @return void
     */
    private function assertRefusedUnderTheLock(): void
    {
        $row = $this->request->fresh();

        self::assertNotNull($row?->voided_at);
        self::assertNotNull($row->completed_at);
        self::assertSame(0, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());
    }

    /**
     * Run the change once the response is validated, before the completion
     * locks.
     *
     * @param  \Closure(): bool  $change
     * @return void
     */
    private function holdAfterValidation(\Closure $change): void
    {
        $validation = static fn (): ValidateResponse => new ValidateResponse(app(ProtocolManager::class), app(ResultBuilder::class), app(VerifiedDeadlines::class));

        app()->bind(ValidateResponse::class, static fn (): CompletionStage => new readonly class ($validation(), $change) implements CompletionStage {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Completion\Stages\ValidateResponse  $inner
             * @param  \Closure(): bool  $change
             */
            public function __construct(

                /** The validation step itself. */
                private ValidateResponse $inner,

                /** What runs once the response is validated. */
                private \Closure $change,
            ) {}

            /**
             * Validate, then run the change.
             *
             * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
             * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
             */
            #[\Override]
            public function run(CompletionState $state): StageOutcome
            {
                $outcome = $this->inner->run($state);

                ($this->change)();

                return $outcome;
            }
        });
    }

    /**
     * Stop trusting the responses' signing certificate; whether it was removed.
     *
     * @return bool
     */
    private function hasDistrustedTheSigningCertificate(): bool
    {
        return app(KeyService::class)->distrustCertificate('tenant-1', $this->connection->id, $this->signingKeyId, Clients::browser())->isSucceeded();
    }

    /**
     * Trust the certificate on the connection, and answer its id.
     *
     * @param  string  $certificate
     * @return string
     */
    private function trust(string $certificate): string
    {
        return app(KeyService::class)->trustCertificate('tenant-1', $this->connection->id, $certificate, Clients::browser())->key->id ?? '';
    }

    /**
     * Complete at the connection's assertion consumer service with the post.
     *
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(): CompletionResult
    {
        return app(CompletionService::class)->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $this->connection->id, $this->post, Clients::browser());
    }

    /**
     * How the completion ended and how many codes it issued.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @return string
     */
    private function outcomeOf(CompletionResult $result): string
    {
        $issuer = app(HandoffIssuer::class);

        assert($issuer instanceof RecordingHandoffIssuer);

        return sprintf('%s:%s:%d', $result->status->value, $result->reason->value ?? '-', count($issuer->grants()));
    }

    /**
     * A valid response to the request, with its `RelayState`.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\CompletionRequest
     */
    private function response(): CompletionRequest
    {
        $endpoints = app(EndpointResolver::class)->endpoints($this->connection);

        return self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, app(Clock::class)->now())
            ->inResponseTo(self::REQUEST_ID)
            ->completionRequest(self::RELAY_STATE);
    }

    /**
     * Fork a process per racer, start them together and collect their reports
     * in order.
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
     * Run the racer on its own connection, reading first in a transaction so
     * its snapshot predates the race.
     *
     * @param  int  $process
     * @param  float  $start
     * @param  \Closure(): string  $work
     * @param  bool  $inTransaction
     * @return never
     */
    private function runInChild(int $process, float $start, \Closure $work, bool $inTransaction): never
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
     * The session's `REPEATABLE READ` statement; PostgreSQL pins the snapshot
     * at the first read.
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
        if (!self::isSignalled($signal)) {
            throw new \RuntimeException(sprintf('The barrier timed out waiting for [%s].', basename($signal)));
        }
    }

    /**
     * Wait up to `SIGNAL_SECONDS` for the signal file; whether it appeared.
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
     * Whether the error, or its cause, is a PostgreSQL serialisation failure
     * (SQLSTATE 40001).
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
     * The trusted identity provider, made once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }
}
