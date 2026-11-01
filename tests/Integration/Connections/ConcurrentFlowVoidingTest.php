<?php

declare(strict_types = 1);

namespace Tests\Integration\Connections;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Races a trust change and a deletion against a flow that inserts through the
 * same connection after the change's snapshot was taken, each in a process of
 * its own with its own database connection, on PostgreSQL and MySQL (SSO-2.11,
 * SSO-2.13, SSO-9.2).
 *
 * The order is forced with signal files, never with timing: the changer runs
 * under `REPEATABLE READ`, inside a transaction of its own that reads the
 * connection, its requests and its codes first, and signals; the flow then
 * starts a request, or completes one inserted after that read and so issues a
 * code, commits and signals; only then does the changer change or delete the
 * connection, which voids what is in flight through it, and commit.
 *
 * On PostgreSQL the changer's updates cannot see a row inserted since its
 * snapshot, so the flow's insert raises the connection's flows version, and the
 * changer fails to serialise (SQLSTATE 40001) when it locks the connection,
 * leaving the connection, the request and the code as the flow left them. On
 * MySQL every locking read and update sees the latest rows, so the change
 * commits with the new request or code voided, or deleted with the connection.
 * Either way, no change commits with a request or code of the connection left
 * neither finished, redeemed nor voided.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InFlightVoider::class)]
#[CoversClass(AuthorizationRequestService::class)]
#[CoversClass(DatabaseHandoffStore::class)]
final class ConcurrentFlowVoidingTest extends TestCase
{
    use UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The tenant the connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var string The issuer the trust change moves the connection to. */
    private const string NEW_ISSUER = 'https://login.example.com';

    /** @var string The protocol state of the request a completion completes. */
    private const string STATE = 'the-protocol-state-of-the-raced-voiding-1';

    /** @var string The S256 challenge of the client's verifier (RFC 7636, appendix B). */
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /** @var float How long, in seconds, a process waits for the other before it gives up. */
    private const float DEADLINE_SECONDS = 30.0;

    /** @var string What a process reports for a serialisation failure. */
    private const string SERIALIZATION_FAILURE = 'serialization_failure';

    /** @var string The change that moves the connection to another issuer. */
    private const string TRUST_CHANGE = 'trust_change';

    /** @var string The change that deletes the connection. */
    private const string DELETION = 'deletion';

    /** @var string The flow that starts a request. */
    private const string START = 'start';

    /** @var string The flow that completes a request and issues a code. */
    private const string COMPLETION = 'completion';

    /** @var ?\SineMacula\Laravel\Sso\Models\Connection The connection changed and flowed through. */
    private ?Connection $connection = null;

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database; bind a fixed clock, a
     * fresh caller, a limiter that allows every attempt and a linker that links
     * every result to one identity; register the application and the driver;
     * create the tables, an enabled connection and the directory the processes
     * use.
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
        $this->app?->instance(Linker::class, new readonly class implements Linker {
            /**
             * One identity for every result.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
             */
            #[\Override]
            public function resolve(VerifiedResult $result): IdentityReference
            {
                unset($result);

                return new IdentityReference('App\Models\User', '42');
            }
        });

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', [
            'web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
        ]);

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => new VerifyingDriver);

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->createDomainsTable();
        self::singleUseMigration()->up(); // @phpstan-ignore method.notFound

        $this->connection = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);
        $this->outcomes   = sys_get_temp_dir() . '/voiding-race-' . bin2hex(random_bytes(8));

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
            self::singleUseMigration()->down(); // @phpstan-ignore method.notFound
            $this->dropDomainsTable();
            $this->dropFlowTables();
            $this->dropConnectionTables();
        }

        parent::tearDown();
    }

    /**
     * Rows of `[change, flow]`: a trust change or a deletion, after a start or
     * a completion.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideRaces(): iterable
    {
        foreach (['a trust change' => self::TRUST_CHANGE, 'a deletion' => self::DELETION] as $changeName => $change) {
            foreach (['a start' => self::START, 'a completion' => self::COMPLETION] as $flowName => $flow) {
                yield "{$changeName} after {$flowName}" => [$change, $flow];
            }
        }
    }

    /**
     * A request started, or a code issued, after the changer's snapshot is
     * never left unvoided by a change that commits: on PostgreSQL the changer
     * fails to serialise and changes nothing; on MySQL it commits, the request
     * or code voided, or deleted with the connection.
     *
     * @param  string  $change
     * @param  string  $flow
     * @return void
     */
    #[DataProvider('provideRaces')]
    public function testAFlowCommittedAfterTheChangersSnapshotIsNeverLeftUnvoided(string $change, string $flow): void
    {
        $read               = "{$this->outcomes}/changer-read";
        $flowed             = "{$this->outcomes}/flow-committed";
        [$changer, $flower] = $this->inProcesses([
            fn (): array => $this->change($change, $read, $flowed),
            fn (): array => $this->flow($flow, $read, $flowed),
        ]);
        $reported  = (string) json_encode([$changer, $flower]);
        $committed = in_array($changer['status'] ?? null, ['updated', 'deleted'], true);

        self::assertSame($flow === self::START ? 'started' : 'completed', $flower['status'] ?? null, $reported);
        self::assertSame(self::expectedChange($change), $changer['status'] ?? null, $reported);
        self::assertSame(self::expectedRows($change, $flow), $this->rows(), $reported);
        self::assertFalse($committed && $this->unvoided() > 0, 'A committed change left a request or code unvoided: ' . $reported);
    }

    /**
     * In a forked process: under `REPEATABLE READ`, inside a transaction of its
     * own, read the connection, its requests and its codes, signal, wait for
     * the flow to commit, then make the change and commit; report the outcome.
     *
     * @param  string  $change
     * @param  string  $read
     * @param  string  $flowed
     * @return array<string, mixed>
     *
     * @throws \Throwable
     */
    private function change(string $change, string $read, string $flowed): array
    {
        $database     = DB::connection(StorageConnection::name());
        $connectionId = (string) $this->connection?->id;

        $database->statement(self::repeatableReadStatement($database->getDriverName()));
        $database->beginTransaction();

        Connection::query()->whereKey($connectionId)->get();
        AuthorizationRequest::query()->where('connection_id', $connectionId)->get();
        HandoffCode::query()->where('connection_id', $connectionId)->get();

        touch($read);
        self::await($flowed);

        $result = $change === self::TRUST_CHANGE
            ? app(ConnectionService::class)->update(self::TENANT, $connectionId, ['settings' => ['issuer' => self::NEW_ISSUER]])
            : app(ConnectionLifecycle::class)->delete(self::TENANT, $connectionId);

        $database->commit();

        return ['status' => $result->status->value];
    }

    /**
     * In a forked process: wait for the changer's read, then start a request,
     * or insert one and complete it, which issues a code; signal once that
     * commits, or fails, and report the outcome.
     *
     * @param  string  $flow
     * @param  string  $read
     * @param  string  $flowed
     * @return array<string, mixed>
     */
    private function flow(string $flow, string $read, string $flowed): array
    {
        $connectionId = (string) $this->connection?->id;

        self::await($read);

        try {
            $status = $flow === self::START
                ? app(AuthorizationRequestService::class)->start('web', Purpose::SIGN_IN, $connectionId)->status->value
                : $this->complete();
        } finally {
            touch($flowed);
        }

        return ['status' => $status];
    }

    /**
     * Insert a `sign_in` request through the connection, bound to the client's
     * challenge, then complete it at the callback with its state; answer how
     * the completion ended.
     *
     * @return string
     *
     * @throws \LogicException
     */
    private function complete(): string
    {
        $connection = $this->connection ?? throw new \LogicException('The race has a connection.');

        $this->makeAuthorizationRequest($connection, [
            'state_digest'      => hash('sha256', self::STATE),
            'handoff_challenge' => self::CHALLENGE,
            'code_verifier'     => app(SecretEncrypter::class)->encrypt('the-pkce-verifier-of-the-raced-voiding-1'),
        ]);

        return app(CompletionService::class)->callback($connection->id, new CompletionRequest('GET', 'state=' . self::STATE, []))->status->value;
    }

    /**
     * What the changer reports: a serialisation failure on PostgreSQL, the
     * change on MySQL.
     *
     * @param  string  $change
     * @return string
     */
    private static function expectedChange(string $change): string
    {
        if (DB::connection()->getDriverName() === 'pgsql') {
            return self::SERIALIZATION_FAILURE;
        }

        return $change === self::TRUST_CHANGE ? 'updated' : 'deleted';
    }

    /**
     * The connection's issuer and the states of its requests and codes once
     * both processes end: as the flow left them on PostgreSQL; on MySQL, the
     * new issuer with the started request or the issued code voided, or nothing
     * left of a deleted connection.
     *
     * @param  string  $change
     * @param  string  $flow
     * @return array{issuer: ?string, requests: list<string>, codes: list<string>}
     */
    private static function expectedRows(string $change, string $flow): array
    {
        $started = $flow === self::START;

        if (DB::connection()->getDriverName() === 'pgsql') {
            return ['issuer' => VerifyingDriver::ISSUER, 'requests' => [$started ? 'open' : 'completed'], 'codes' => $started ? [] : ['open']];
        }

        if ($change === self::DELETION) {
            return ['issuer' => null, 'requests' => [], 'codes' => []];
        }

        return ['issuer' => self::NEW_ISSUER, 'requests' => [$started ? 'voided' : 'completed'], 'codes' => $started ? [] : ['voided']];
    }

    /**
     * The connection's issuer, `null` once it is deleted, and the state of each
     * of its requests and codes, in id order.
     *
     * @return array{issuer: ?string, requests: list<string>, codes: list<string>}
     */
    private function rows(): array
    {
        $connectionId = (string) $this->connection?->id;
        $issuer       = Connection::query()->find($connectionId)?->settings['issuer'] ?? null;

        $requests = AuthorizationRequest::query()->where('connection_id', $connectionId)->orderBy('id')->get()->all();
        $codes    = HandoffCode::query()->where('connection_id', $connectionId)->orderBy('id')->get()->all();

        $request = static fn (AuthorizationRequest $row): string => self::state($row->voided_at !== null, $row->completed_at !== null, 'completed');
        $code    = static fn (HandoffCode $row): string => self::state($row->voided_at !== null, $row->redeemed_at !== null, 'redeemed');

        return [
            'issuer'   => is_string($issuer) ? $issuer : null,
            'requests' => array_values(array_map($request, $requests)),
            'codes'    => array_values(array_map($code, $codes)),
        ];
    }

    /**
     * How many of the connection's requests and codes are neither finished,
     * redeemed nor voided.
     *
     * @return int
     */
    private function unvoided(): int
    {
        $connectionId = (string) $this->connection?->id;
        $requests     = AuthorizationRequest::query()->where('connection_id', $connectionId)->whereNull('completed_at')->whereNull('voided_at')->count();
        $codes        = HandoffCode::query()->where('connection_id', $connectionId)->whereNull('redeemed_at')->whereNull('voided_at')->count();

        return $requests + $codes;
    }

    /**
     * A row's state: `voided`, the end it reached, or `open`.
     *
     * @param  bool  $voided
     * @param  bool  $ended
     * @param  string  $end
     * @return string
     */
    private static function state(bool $voided, bool $ended, string $end): string
    {
        if ($voided) {
            return 'voided';
        }

        return $ended ? $end : 'open';
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
     * Wait until the other process has signalled, or the deadline passes.
     *
     * @param  string  $signal
     * @return void
     */
    private static function await(string $signal): void
    {
        $deadline = microtime(true) + self::DEADLINE_SECONDS;

        while (!file_exists($signal) && microtime(true) < $deadline) {
            usleep(5000);
        }
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
     * serialisation failure: SQLSTATE 40001 on PostgreSQL, where a deadlock is
     * 40P01 instead. Inside the changer's own transaction, Laravel rethrows it
     * as a `DeadlockException` whose previous error is the query's.
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
     * The shipped migration of the single-use keys.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function singleUseMigration(): Migration
    {
        return require dirname(__DIR__, 3) . self::SINGLE_USE_MIGRATION;
    }
}
