<?php

declare(strict_types = 1);

namespace Tests\Integration\Enforcement;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection as DatabaseConnection;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementFinder;
use SineMacula\Laravel\Sso\Enforcement\EnforcementLock;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesEnforcement;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Enforcement\TableSessions;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Races a redemption, which writes the application's session inside its own
 * transaction, against a change that turns the tenant's enforcement on with
 * another connection, each in a process of its own with its own database
 * connection, on PostgreSQL and MySQL (SSO-4.5, SSO-4.6, SSO-9.9, decision D5).
 *
 * Both orders are forced with signal files and the database's own lock waits,
 * never with timing: the redeemer first, holding the tenant's enforcement lock
 * until the database shows the change waiting on it; and the change first,
 * holding the lock from inside its revocation until the database shows the
 * redemption waiting on it. Each runs for a tenant whose rule is already stored
 * (off) and for one with no row at all, and with each process plain and again
 * inside a transaction of its own that read the tables before the race, so a
 * decision answered from that older snapshot (MySQL's `REPEATABLE READ`) would
 * fail it.
 *
 * Once both transactions end, no committed session may violate the committed
 * rule: the redemption that held the lock first has its session revoked by the
 * change that waited (whose revocation deletes with a current read), and the
 * redemption that waited sees the rule and refuses. The process that holds the
 * lock first always reaches its own outcome. For the process that waited, a
 * PostgreSQL serialisation failure (SQLSTATE 40001) is an accepted, safe
 * outcome; a MySQL deadlock, which MySQL also reports as SQLSTATE 40001, is an
 * error and fails the race.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(DatabaseEnforcement::class)]
#[CoversClass(EnforcementLock::class)]
#[CoversClass(EnforcementService::class)]
final class EnforcementAdmissionRaceTest extends TestCase
{
    use UsesConnections, UsesEnforcement, UsesFlowTables;

    /** @var string The tenant whose enforcement changes. */
    private const string TENANT = 'tenant-1';

    /** @var string The client's verifier (RFC 7636, appendix B). */
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var float How long, in seconds, a process waits for the other before it gives up. */
    private const float DEADLINE_SECONDS = 30.0;

    /** @var string What a process reports for a serialisation failure. */
    private const string SERIALIZATION_FAILURE = 'serialization_failure';

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the code was issued through. */
    private Connection $redeemed;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the change turns enforcement on with. */
    private Connection $other;

    /** @var \Tests\Fixtures\Enforcement\TableSessions The sessions and their revocation. */
    private TableSessions $sessions;

    /** @var string The code the redeemer redeems. */
    private string $code;

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database; bind a fixed clock, a
     * fresh caller, a limiter that allows every attempt, a linker and the
     * session table's revocation; switch the features on; create the tables,
     * the two connections, the code and the directory the processes use.
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

        $this->sessions = new TableSessions;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(SessionRevocation::class, $this->sessions);
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
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result): LinkResolution
            {
                unset($result);

                return ExampleLinks::resolution(new IdentityReference('App\Models\User', '42'));
            }
        });

        $driver = new VerifyingDriver;

        Config::set('sso.features.oidc', true);
        Config::set('sso.features.enforcement', true);

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->createEnforcementTable();
        self::singleUseMigration()->up(); // @phpstan-ignore method.notFound
        TableSessions::create();

        $usable         = ['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'has_completed_sign_in' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]];
        $this->redeemed = $this->makeConnection($usable);
        $this->other    = $this->makeConnection($usable);
        $this->code     = $this->issue();
        $this->outcomes = sys_get_temp_dir() . '/admission-race-' . bin2hex(random_bytes(8));

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

        if (isset($this->code)) {
            TableSessions::drop();
            self::singleUseMigration()->down(); // @phpstan-ignore method.notFound
            $this->dropEnforcementTable();
            $this->dropFlowTables();
            $this->dropConnectionTables();
        }

        parent::tearDown();
    }

    /**
     * Rows of `[order, stored, readFirst]`: which process takes the lock first,
     * whether the tenant's rule is already stored (off) or it has no row, and
     * whether each process runs inside a transaction of its own that read the
     * tables first.
     *
     * @return iterable<string, array{0: string, 1: bool, 2: bool}>
     */
    public static function provideRaces(): iterable
    {
        foreach (['redeemer first', 'enabler first'] as $order) {
            foreach (['a stored rule' => true, 'no row' => false] as $row => $stored) {
                foreach (['plainly' => false, 'after a read in a caller\'s transaction' => true] as $mode => $readFirst) {
                    yield "{$order}, {$row}, {$mode}" => [$order, $stored, $readFirst];
                }
            }
        }
    }

    /**
     * However the redemption and the change interleave, no committed session
     * violates the committed rule: a redemption that held the lock first is
     * redeemed and its session revoked by the change, which waited for it; a
     * redemption that waited for the change is refused with
     * `enforcement_unsatisfied` and writes no session. The process that held
     * the lock reaches its own outcome; a PostgreSQL serialisation failure is
     * accepted only for the one that waited.
     *
     * @param  string  $order
     * @param  bool  $stored
     * @param  bool  $readFirst
     * @return void
     */
    #[DataProvider('provideRaces')]
    public function testNoSessionSurvivesThatViolatesTheCommittedRule(string $order, bool $stored, bool $readFirst): void
    {
        if ($stored) {
            self::assertTrue($this->service()->update(self::TENANT, false, [$this->other->id])->isChanged());
        }

        $redeemerFirst        = $order === 'redeemer first';
        [$redeemer, $enabler] = $this->inProcesses($this->racers($redeemerFirst, $readFirst));
        $reported             = (string) json_encode([$redeemer, $enabler]);

        [$holder, $waiter] = $redeemerFirst ? [$redeemer, $enabler] : [$enabler, $redeemer];

        self::assertSame($redeemerFirst ? 'redeemed' : 'updated', $holder['status'] ?? null, $reported);
        self::assertContains($waiter['status'] ?? null, self::acceptedForTheWaiter($redeemerFirst ? 'updated' : 'refused:enforcement_unsatisfied'), $reported);
        self::assertTrue($holder['sawWaiter'] ?? false, 'The second process never waited on the lock: ' . $reported);

        $this->assertNoSessionViolatesTheRule($reported);
    }

    /**
     * What the process that waited may report: its own outcome, or, on
     * PostgreSQL only, a serialisation failure.
     *
     * @param  string  $outcome
     * @return list<string>
     */
    private static function acceptedForTheWaiter(string $outcome): array
    {
        return DB::connection()->getDriverName() === 'pgsql' ? [$outcome, self::SERIALIZATION_FAILURE] : [$outcome];
    }

    /**
     * The two racers, the redeemer's and the change's: the one that goes first
     * signals once it holds the lock and holds it until the other waits on it;
     * the other waits for that signal before it starts.
     *
     * @param  bool  $redeemerFirst
     * @param  bool  $readFirst
     * @return list<\Closure(): array<string, mixed>>
     */
    private function racers(bool $redeemerFirst, bool $readFirst): array
    {
        if ($redeemerFirst) {

            $signal = "{$this->outcomes}/redeemer-locked";

            return [fn (): array => $this->redeem($readFirst, null, $signal), fn (): array => $this->enable($readFirst, $signal, null)];
        }

        $signal = "{$this->outcomes}/enabler-locked";

        return [fn (): array => $this->redeem($readFirst, $signal, null), fn (): array => $this->enable($readFirst, null, $signal)];
    }

    /**
     * Assert every committed session of the tenant was established through a
     * connection the committed rule allows, and that a change that committed
     * left no session through the connection it excludes.
     *
     * @param  string  $reported
     * @return void
     */
    private function assertNoSessionViolatesTheRule(string $reported): void
    {
        $rule     = (new EnforcementFinder)->find(self::TENANT);
        $sessions = TableSessions::connectionsOf(self::TENANT);

        if ($rule?->enabled !== true) {
            return;
        }

        self::assertSame([$this->other->id], $rule->connection_ids, $reported);
        self::assertSame([], array_values(array_diff($sessions, $rule->connection_ids)), 'A session survived the rule: ' . $reported);
        self::assertSame([], $sessions, $reported);
    }

    /**
     * In a forked process: open the redeemer's transaction, read the tables
     * first when asked, wait for the change's signal when told to, redeem the
     * code and write the session when it is redeemed, then, when told to,
     * signal and hold the transaction until the database shows the change
     * waiting on it; commit, and report.
     *
     * @param  bool  $readFirst
     * @param  ?string  $awaited
     * @param  ?string  $signal
     * @return array<string, mixed>
     */
    private function redeem(bool $readFirst, ?string $awaited, ?string $signal): array
    {
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        if ($readFirst) {
            self::readTheTables();
        }

        if ($awaited !== null) {
            self::await($awaited);
        }

        $answer = app(HandoffRedemption::class)->redeem(Purpose::SIGN_IN, 'web', $this->redeemed->id, $this->code, self::VERIFIER);

        if ($answer->isRedeemed()) {
            TableSessions::write(self::TENANT, $this->redeemed->id);
        }

        $sawWaiter = $signal !== null && self::hasAWaiterOnceSignalled($database, $signal);

        $database->commit();

        return ['status' => $answer->isRedeemed() ? 'redeemed' : 'refused:' . $answer->reason?->value, 'sawWaiter' => $sawWaiter];
    }

    /**
     * In a forked process: inside a transaction of its own that read the tables
     * first when asked, wait for the redeemer's signal when told to, and turn
     * the tenant's enforcement on with the other connection; when told to, the
     * revocation signals and holds the change's transaction until the database
     * shows the redemption waiting on it. Report the outcome.
     *
     * @param  bool  $readFirst
     * @param  ?string  $awaited
     * @param  ?string  $signal
     * @return array<string, mixed>
     */
    private function enable(bool $readFirst, ?string $awaited, ?string $signal): array
    {
        $database = DB::connection(StorageConnection::name());

        /** @var \ArrayObject<int, bool> $sawWaiter */
        $sawWaiter = new \ArrayObject;

        if ($signal !== null) {
            $this->sessions->afterRevoking = static function () use ($database, $signal, $sawWaiter): void {
                $sawWaiter[] = self::hasAWaiterOnceSignalled($database, $signal);
            };
        }

        if ($readFirst) {
            $database->beginTransaction();
            self::readTheTables();
        }

        if ($awaited !== null) {
            self::await($awaited);
        }

        $result = $this->service()->update(self::TENANT, true, [$this->other->id]);

        if ($readFirst) {
            $database->commit();
        }

        return ['status' => $result->status->value, 'sawWaiter' => $sawWaiter[0] ?? false];
    }

    /**
     * Read every table the race touches, plainly, so a transaction's
     * `REPEATABLE READ` snapshot is taken before the race.
     *
     * @return void
     */
    private static function readTheTables(): void
    {
        TenantEnforcement::query()->get();
        Connection::query()->get();
        StoredCode::query()->get();
        TableSessions::connectionsOf(self::TENANT);
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
     * Signal the other process, then poll, on the connection that holds the
     * lock, until another session waits on a lock it holds, or the deadline
     * passes; answer whether one did.
     *
     * @param  \Illuminate\Database\Connection  $database
     * @param  string  $signal
     * @return bool
     *
     * @throws \LogicException
     */
    private static function hasAWaiterOnceSignalled(DatabaseConnection $database, string $signal): bool
    {
        touch($signal);

        $query    = self::waitersQuery($database->getDriverName());
        $deadline = microtime(true) + self::DEADLINE_SECONDS;

        do {

            $row = $database->selectOne($query, [], false);

            if ($row instanceof \stdClass && (int) ($row->waiting ?? 0) > 0) {
                return true;
            }

            usleep(10000);
        } while (microtime(true) < $deadline);

        return false;
    }

    /**
     * The query that counts the sessions waiting on a lock the current session
     * holds.
     *
     * @param  string  $driver
     * @return string
     *
     * @throws \LogicException
     */
    private static function waitersQuery(string $driver): string
    {
        return match ($driver) {
            'pgsql' => 'select count(*) as waiting from pg_stat_activity where pg_backend_pid() = any(pg_blocking_pids(pid))',
            'mysql' => 'select count(*) as waiting from performance_schema.data_lock_waits where BLOCKING_THREAD_ID = ps_current_thread_id()',
            default => throw new \LogicException(sprintf('No query finds the sessions waiting on a lock on [%s].', $driver)),
        };
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
     * threw (a MySQL deadlock, also SQLSTATE 40001, among them), and end
     * without running the parent's shutdown, which rolls back whatever it left
     * open.
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
     * 40P01 instead. Inside a caller's transaction, Laravel rethrows it as a
     * `DeadlockException` whose previous error is the query's. On MySQL, 40001
     * is a deadlock (error 1213), which the race must never meet.
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
     * Issue a linked `sign_in` code for `web` through the redeemed connection,
     * bound to the client's verifier.
     *
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function issue(): string
    {
        $result = new VerifiedResult(
            issuer: VerifyingDriver::ISSUER,
            subject: VerifyingDriver::SUBJECT,
            nameIdFormat: null,
            connectionId: $this->redeemed->id,
            tenantId: self::TENANT,
            protocol: VerifyingDriver::NAME,
            application: 'web',
            purpose: Purpose::SIGN_IN,
            requestReference: RequestReference::fromString('Rq8tVv3w0kLmNoPqRsTuVwXyZ0123456'),
            attributes: [],
            emailDomainVerified: false,
            authenticationContext: new AuthenticationContext(CarbonImmutable::parse('2026-11-01T09:29:00Z'), ['pwd']),
        );

        $grant = new HandoffGrant(
            result: $result,
            challenge: S256Challenge::fromString('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'),
            expiresAt: CarbonImmutable::parse('2026-11-01T09:31:00Z'),
            linkedIdentity: new IdentityReference('App\Models\User', '42'),
            linkId: 'link-42',
        );

        return app(DatabaseHandoffStore::class)->issue($grant)->code->reveal();
    }

    /**
     * The enforcement helper, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementService
     */
    private function service(): EnforcementService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(EnforcementService::class);
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
