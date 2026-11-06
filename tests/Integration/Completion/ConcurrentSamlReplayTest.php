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
use SineMacula\Laravel\Sso\Completion\Stages\RecordReplay;
use SineMacula\Laravel\Sso\Completion\Stages\ValidateResponse;
use SineMacula\Laravel\Sso\Completion\VerifiedDeadlines;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\TestCase;

/**
 * Races the replay of one SAML assertion across processes, each with its own
 * database connection, on PostgreSQL and MySQL (SSO-6.6, SSO-11.5): two
 * requests whose responses carry the same assertion id, completed at once, give
 * exactly one handoff and one `replayed`, and exactly one record of the
 * assertion. Each completer validates its response, signals that it has, and
 * waits for the other's signal before it takes the completion's locks, so both
 * reach the locked recording together however loaded the machine. A completion
 * runs outside any transaction on the storage connection, so each completer
 * runs plainly. On PostgreSQL alone a completer may instead fail to serialise
 * (SQLSTATE `40001`), which is a safe outcome: it issued nothing.
 *
 * Sequentially, on every database, an assertion that fails validation is never
 * recorded, and the same assertion id under another connection or issuer is
 * recorded apart.
 *
 * The race is skipped on SQLite, whose in-memory database each process would
 * have to itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(RecordReplay::class)]
#[CoversClass(AssertionValidator::class)]
final class ConcurrentSamlReplayTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var string The assertion id both responses carry. */
    private const string ASSERTION_ID = '_assertion-raced-1';

    /** @var float Seconds a racer waits for the other's signal before it gives up. */
    private const float SIGNAL_SECONDS = 10.0;

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The SAML connection both requests were started through. */
    private Connection $connection;

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /**
     * Bind a fixed clock, a limiter that allows every attempt and the recording
     * issuer, configure SAML, the endpoints and the application, create the
     * tables and a connection that trusts the identity provider, and make the
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

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
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

        $this->connection = $this->samlConnection();
        $this->outcomes   = sys_get_temp_dir() . '/saml-replay-race-' . bin2hex(random_bytes(8));

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
     * Two requests whose responses carry the same assertion id, completed at
     * once: exactly one completes with a code, the other is refused with
     * `replayed` (or, on PostgreSQL only, fails to serialise), and the
     * assertion is recorded once.
     *
     * @return void
     */
    public function testExactlyOneOfTwoResponsesCarryingOneAssertionCompletes(): void
    {
        $this->requireRacingProcesses();

        $first  = $this->posted('_request-race-a', 'relay-state-of-race-a');
        $second = $this->posted('_request-race-b', 'relay-state-of-race-b');

        $outcomes = $this->race([$first, $second]);
        $listed   = implode(', ', $outcomes);
        $refused  = array_filter($outcomes, static fn (string $outcome): bool => $outcome === 'failed:replayed:0' || $outcome === 'serialization');

        self::assertCount(1, array_keys($outcomes, 'completed:-:1', true), $listed);
        self::assertCount(1, $refused, $listed);
        self::assertSame(1, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());
    }

    /**
     * Sequentially, an assertion that fails validation records nothing, so the
     * same assertion, valid, still completes once; and its id under another
     * connection is recorded apart.
     *
     * @return void
     */
    public function testAnInvalidAssertionIsNeverRecorded(): void
    {
        $invalid = $this->posted('_request-seq-a', 'relay-state-of-seq-a', ['audiences' => [['https://other.example.test/saml']]]);
        $valid   = $this->posted('_request-seq-b', 'relay-state-of-seq-b');

        self::assertSame(FailureReason::AUDIENCE_MISMATCH, $this->complete($this->connection, $invalid)->reason);
        self::assertSame(0, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());
        self::assertTrue($this->complete($this->connection, $valid)->isCompleted());

        $other = $this->samlConnection();

        self::assertTrue($this->complete($other, $this->posted('_request-seq-c', 'relay-state-of-seq-c', [], $other))->isCompleted());
        self::assertSame(2, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());
    }

    /**
     * Skip where processes cannot share the database.
     *
     * @return void
     */
    private function requireRacingProcesses(): void
    {
        $shared = DB::connection()->getDriverName() !== 'sqlite' && function_exists('pcntl_fork');

        if ($shared) {
            return;
        }

        self::markTestSkipped('Racing processes need a shared database server and pcntl.');
    }

    /**
     * Store a request through the connection and answer what the browser posts
     * for it: a valid response carrying the shared assertion id, with the
     * changes given, and the request's `RelayState`.
     *
     * @param  string  $requestId
     * @param  string  $relayState
     * @param  array<string, mixed>  $changes
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Protocols\CompletionRequest
     */
    private function posted(string $requestId, string $relayState, array $changes = [], ?Connection $connection = null): CompletionRequest
    {
        $connection ??= $this->connection;

        $this->makeAuthorizationRequest($connection, ['saml_request_id' => $requestId, 'state_digest' => hash('sha256', $relayState)]);

        $endpoints = app(EndpointResolver::class)->endpoints($connection);
        $response  = self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, app(Clock::class)->now());

        return $response->with(['assertion_id' => self::ASSERTION_ID, ...$changes])->inResponseTo($requestId)->completionRequest($relayState);
    }

    /**
     * Complete at the connection's assertion consumer service.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(Connection $connection, CompletionRequest $request): CompletionResult
    {
        return app(CompletionService::class)->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $connection->id, $request, Clients::browser());
    }

    /**
     * Fork a completer for each post, have each start at the same moment on a
     * connection of its own, and collect what each reported, in order.
     *
     * @param  list<\SineMacula\Laravel\Sso\Protocols\CompletionRequest>  $posts
     * @return list<string>
     */
    private function race(array $posts): array
    {
        DB::disconnect();

        $start = microtime(true) + 0.5;
        $pids  = [];

        foreach ($posts as $process => $post) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, count($posts), $start, $post);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        $outcomes = [];

        foreach (array_keys($posts) as $process) {
            $outcomes[] = (string) file_get_contents("{$this->outcomes}/{$process}");
        }

        return $outcomes;
    }

    /**
     * In a forked process: open a connection of its own, hold the completion
     * once it has validated until every racer has, complete, report how it
     * ended and how many codes it issued, and end without running the parent's
     * shutdown.
     *
     * @param  int  $process
     * @param  int  $racers
     * @param  float  $start
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $post
     * @return never
     */
    private function runInChild(int $process, int $racers, float $start, CompletionRequest $post): never
    {
        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            $this->holdAfterValidation($process, $racers);

            $wait = $start - microtime(true);

            if ($wait > 0) {
                usleep((int) ($wait * 1000000));
            }

            $result = app(CompletionService::class)->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $this->connection->id, $post, Clients::browser());
            $issuer = app(HandoffIssuer::class);

            assert($issuer instanceof RecordingHandoffIssuer);

            $outcome = sprintf('%s:%s:%d', $result->status->value, $result->reason->value ?? '-', count($issuer->grants()));
        } catch (\Throwable $e) {
            $outcome = self::isSerializationFailure($e) ? 'serialization' : 'error: ' . $e::class . ': ' . $e->getMessage();
        }

        file_put_contents("{$this->outcomes}/{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Bind the validation step to one that, once the response is validated,
     * signals it and waits for every racer's signal before the completion takes
     * its locks.
     *
     * @param  int  $process
     * @param  int  $racers
     * @return void
     */
    private function holdAfterValidation(int $process, int $racers): void
    {
        $directory = $this->outcomes;
        $barrier   = static function () use ($directory, $process, $racers): void {

            touch("{$directory}/validated-{$process}");

            for ($other = 0; $other < $racers; $other++) {
                self::await("{$directory}/validated-{$other}");
            }
        };

        $validation = static fn (): ValidateResponse => new ValidateResponse(app(ProtocolManager::class), app(ResultBuilder::class), app(VerifiedDeadlines::class));

        app()->bind(ValidateResponse::class, static fn (): CompletionStage => new readonly class ($validation(), $barrier) implements CompletionStage {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Completion\Stages\ValidateResponse  $inner
             * @param  \Closure(): void  $barrier
             */
            public function __construct(

                /** The validation step itself. */
                private ValidateResponse $inner,

                /** What holds the completion once it has validated. */
                private \Closure $barrier,
            ) {}

            /**
             * Validate, then wait at the barrier.
             *
             * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
             * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
             */
            #[\Override]
            public function run(CompletionState $state): StageOutcome
            {
                $outcome = $this->inner->run($state);

                ($this->barrier)();

                return $outcome;
            }
        });
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
     * serialisation failure (SQLSTATE 40001), which a completion may meet only
     * there.
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
     * A usable SAML connection that trusts the identity provider.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \LogicException
     */
    private function samlConnection(): Connection
    {
        $connection = $this->makeConnection([
            'protocol' => 'saml2',
            'enabled'  => true,
            'settings' => ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL],
        ]);
        $certificate = self::idp()->certificate();
        $details     = openssl_pkey_get_details(openssl_pkey_get_public($certificate) ?: throw new \LogicException('A certificate has a public key.'));

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $certificate,
            'public_key'    => is_array($details) ? $details['key'] : '',
            'fingerprint'   => (string) openssl_x509_fingerprint($certificate, 'sha256'),
        ])->save();

        return $connection;
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
