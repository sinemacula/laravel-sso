<?php

declare(strict_types = 1);

namespace Tests\Integration\Completion;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Stages\ConsumeRequest;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Races completions across processes, each with its own database connection, on
 * PostgreSQL and MySQL (SSO-5.1, SSO-5.6, SSO-11.5, SSO-2.11):
 *
 * - completions of one response, however they interleave: exactly one
 *   completes, and every other is rejected with `request_unknown`;
 * - a completion racing a change that voids its connection's unfinished
 *   requests under the connection's lock (as disabling the connection does): a
 *   request voided while its response was validated is refused under the lock
 *   and no code is issued for it.
 *
 * A completion runs outside any transaction on the storage connection, so every
 * completer is plain. The change runs plain, and again inside a transaction of
 * its own that read the request before the race began, so its write must see
 * what the completion committed rather than its transaction's snapshot (MySQL's
 * `REPEATABLE READ`). The change waits for the completion to signal that it is
 * validating, and the completion waits for the change to signal that it voided,
 * so the order the test asserts is the order they run in, however loaded the
 * machine.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(ConsumeRequest::class)]
final class ConcurrentCompletionTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var int Processes racing to complete one response. */
    private const int COMPLETERS = 4;

    /** @var string The protocol state the request was started with. */
    private const string STATE = 'the-protocol-state-of-the-raced-completion-1';

    /** @var float Seconds a racer waits for the other's signal before it gives up. */
    private const float SIGNAL_SECONDS = 10.0;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the request was started through. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Models\AuthorizationRequest The request every process races for. */
    private AuthorizationRequest $request;

    /** @var \Tests\Fixtures\Protocols\VerifyingDriver The driver the connection runs over. */
    private VerifyingDriver $driver;

    /** @var string Directory the processes report their outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, bind a fixed clock, a
     * limiter that allows every attempt and the recording issuer, register the
     * application and the driver, create the tables, the connection and the
     * request, and make the directory the processes report in.
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

        $this->driver = new VerifyingDriver;

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

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', [
            'web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true, 'unlinked_handoffs' => true],
        ]);

        $driver = $this->driver;

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);
        $this->request    = $this->makeAuthorizationRequest($this->connection, [
            'state_digest'      => hash('sha256', self::STATE),
            'handoff_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_verifier'     => app(SecretEncrypter::class)->encrypt('the-pkce-verifier-of-the-raced-completion-1'),
        ]);

        $this->outcomes = sys_get_temp_dir() . '/completion-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove this test's outcomes.
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
     * Completions of one response: exactly one completes, and every other is
     * rejected with `request_unknown`.
     *
     * @return void
     */
    public function testExactlyOneOfTheCompletionsOfOneResponseCompletes(): void
    {
        $this->assertCompletedOnce($this->race(array_fill(0, self::COMPLETERS, [$this->completer(), false])));
    }

    /**
     * A change that voids the request while its response is validated is waited
     * for by nothing: the completion finds the request voided under the lock,
     * fails with `connection_unavailable`, and issues no code.
     *
     * @return void
     */
    public function testACompletionNeverIssuesACodeForARequestVoidedWhileItValidated(): void
    {
        $this->assertVoidedWhileValidating(false);
    }

    /**
     * The same race, the change inside a transaction of its own that read the
     * request before the race began.
     *
     * @return void
     */
    public function testACompletionNeverIssuesACodeForARequestVoidedInsideACallersTransaction(): void
    {
        $this->assertVoidedWhileValidating(true);
    }

    /**
     * Race a completion against a change that voids its request once the
     * completion signals it is validating; the completion validates until the
     * change signals it voided. Assert the completion failed with
     * `connection_unavailable` and issued no code, and the request is voided
     * and finished.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    private function assertVoidedWhileValidating(bool $inTransaction): void
    {
        $validating = "{$this->outcomes}/validating";
        $voided     = "{$this->outcomes}/voided";

        $this->driver->onComplete = static function () use ($validating, $voided): void {
            touch($validating);
            self::isSignalled($voided);
        };

        $outcomes = $this->race([[$this->completer(), false], [$this->voider($validating, $voided), $inTransaction]]);
        $row      = $this->reread();

        self::assertSame(['failed:connection_unavailable:0', 'voided:1'], $outcomes);
        self::assertNotNull($row->voided_at);
        self::assertNotNull($row->completed_at);
    }

    /**
     * Assert exactly one process completed with one code, every other was
     * rejected with `request_unknown` and issued nothing, and the request is
     * consumed and completed.
     *
     * @param  list<string>  $outcomes
     * @return void
     */
    private function assertCompletedOnce(array $outcomes): void
    {
        $listed = implode(', ', $outcomes);

        self::assertCount(1, array_keys($outcomes, 'completed:-:1', true), $listed);
        self::assertCount(self::COMPLETERS - 1, array_keys($outcomes, 'rejected:request_unknown:0', true), $listed);
        self::assertNotNull($this->reread()->consumed_at);
        self::assertNotNull($this->reread()->completed_at);
        self::assertSame(1, DB::table(StorageConnection::table('single_use.table'))->count());
    }

    /**
     * What a completing process does: complete at the callback with the state
     * and report how it ended and how many codes it issued.
     *
     * @return \Closure(): string
     */
    private function completer(): \Closure
    {
        $connectionId = $this->connection->id;

        return static function () use ($connectionId): string {
            $result = app(CompletionService::class)->callback($connectionId, new CompletionRequest('GET', 'state=' . self::STATE, []));
            $issuer = app(HandoffIssuer::class);

            assert($issuer instanceof RecordingHandoffIssuer);

            return sprintf('%s:%s:%d', $result->status->value, $result->reason->value ?? '-', count($issuer->grants()));
        };
    }

    /**
     * What a voiding process does, as disabling the connection does: once the
     * completion signals it is validating, lock the connection's row, void its
     * unfinished requests in the same transaction, signal that it voided, and
     * report how many it voided.
     *
     * @param  string  $validating
     * @param  string  $voided
     * @return \Closure(): string
     */
    private function voider(string $validating, string $voided): \Closure
    {
        $connectionId = $this->connection->id;

        return static function () use ($connectionId, $validating, $voided): string {
            if (!self::isSignalled($validating)) {
                return 'error: the completion never signalled it was validating';
            }

            $count = DB::connection(StorageConnection::name())->transaction(static function () use ($connectionId): int {

                Connection::query()->useWritePdo()->lockForUpdate()->whereKey($connectionId)->first();

                return AuthorizationRequest::query()
                    ->where('connection_id', $connectionId)
                    ->whereNull('completed_at')
                    ->whereNull('voided_at')
                    ->update(['voided_at' => app(Clock::class)->now()]);
            });

            touch($voided);

            return 'voided:' . $count;
        };
    }

    /**
     * Wait for the other racer to signal, by creating the file, for at most
     * `SIGNAL_SECONDS`; whether it did.
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
     * In a forked process: open a connection of its own, wait for its start, do
     * its work, report the outcome, and end without running the parent's
     * shutdown.
     *
     * Racing inside a transaction, the process opens one and reads the request
     * before the start, so the transaction's snapshot predates every other
     * process's work, and commits after its own.
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
                $database->beginTransaction();
                AuthorizationRequest::query()->whereKey($this->request->id)->get();
            }

            $wait = $start - microtime(true);

            if ($wait > 0) {
                usleep((int) ($wait * 1000000));
            }

            $outcome = $work();

            if ($inTransaction) {
                $database->commit();
            }
        } catch (\Throwable $e) {
            $outcome = 'error: ' . $e::class . ': ' . $e->getMessage();
        }

        file_put_contents("{$this->outcomes}/{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * The request, read again.
     *
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function reread(): AuthorizationRequest
    {
        return AuthorizationRequest::query()->whereKey($this->request->id)->sole();
    }
}
