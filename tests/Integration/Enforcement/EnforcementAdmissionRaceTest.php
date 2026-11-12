<?php

declare(strict_types = 1);

namespace Tests\Integration\Enforcement;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection as DatabaseConnection;
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
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
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
use Tests\Fixtures\Clients;
use Tests\Fixtures\Enforcement\TableSessions;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Integration tests racing a redemption against turning enforcement on.
 *
 * Orders are forced with signal files and lock waits, never timing. Skipped on
 * SQLite and without `pcntl`.
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
    use UsesConnections;

    /** @var string The tenant whose enforcement changes. */
    private const string TENANT = 'tenant-1';

    /** @var string The client's verifier (RFC 7636, appendix B). */
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

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
     * Skip where processes cannot share the database, then set up the features,
     * the two connections, the code and the signal directory.
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
             * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
            {
                unset($result);

                return ExampleLinks::resolution(new IdentityReference('App\Models\User', '42'));
            }
        });

        $driver = new VerifyingDriver;

        Config::set('sso.features.oidc', true);
        Config::set('sso.features.enforcement', true);

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->usePackageTables();
        TableSessions::create();

        $usable         = ['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'has_completed_sign_in' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]];
        $this->redeemed = $this->makeConnection($usable);
        $this->other    = $this->makeConnection($usable);
        $this->code     = $this->issue();
        $this->outcomes = sys_get_temp_dir() . '/admission-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the signals and outcomes and drop the sessions table.
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
        }

        parent::tearDown();
    }

    /**
     * Rows of `[order, stored, readFirst]`.
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
     * However the two interleave, no committed session violates the committed
     * rule.
     *
     * Only the process that waited may fail with a PostgreSQL serialisation
     * failure.
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
            self::assertTrue($this->service()->update(self::TENANT, false, [$this->other->id], Clients::browser())->isChanged());
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
     * What the process that waited may report.
     *
     * @param  string  $outcome
     * @return list<string>
     */
    private static function acceptedForTheWaiter(string $outcome): array
    {
        return DB::connection()->getDriverName() === 'pgsql' ? [$outcome, self::SERIALIZATION_FAILURE] : [$outcome];
    }

    /**
     * The redeemer and the changer, the first holding the lock until the other
     * waits.
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
     * Assert every committed session went through a connection the committed
     * rule allows.
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
     * In a forked process: redeem the code and write the session, holding the
     * lock when told to.
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

        $answer = DB::connection(StorageConnection::name())->transaction(
            fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $this->redeemed->id, $this->code, self::VERIFIER, Clients::browser()),
        );

        if ($answer->isRedeemed()) {
            TableSessions::write(self::TENANT, $this->redeemed->id);
        }

        $sawWaiter = $signal !== null && self::hasAWaiterOnceSignalled($database, $signal);

        $database->commit();

        return ['status' => $answer->isRedeemed() ? 'redeemed' : 'refused:' . $answer->reason?->value, 'sawWaiter' => $sawWaiter];
    }

    /**
     * In a forked process: turn enforcement on, holding the lock in the
     * revocation when told to.
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

        $result = $this->service()->update(self::TENANT, true, [$this->other->id], Clients::browser());

        if ($readFirst) {
            $database->commit();
        }

        return ['status' => $result->status->value, 'sawWaiter' => $sawWaiter[0] ?? false];
    }

    /**
     * Read every table the race touches, so a `REPEATABLE READ` snapshot is
     * taken first.
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
     * Signal the other process, then poll until it waits on this one's lock.
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
     * The query counting sessions waiting on a lock the current session holds.
     *
     * @param  string  $driver
     * @return string
     *
     * @throws \LogicException
     */
    private static function waitersQuery(string $driver): string
    {
        return match ($driver) {
            'pgsql' => 'select count(*) as waiting from (select distinct pid from pg_locks where not granted) as waits where pg_backend_pid() = any(pg_blocking_pids(waits.pid))',
            'mysql' => 'select count(*) as waiting from performance_schema.data_lock_waits where BLOCKING_THREAD_ID = ps_current_thread_id()',
            default => throw new \LogicException(sprintf('No query finds the sessions waiting on a lock on [%s].', $driver)),
        };
    }

    /**
     * Fork a process per body and collect what each reported, in order.
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
     * In a forked process: run the body on a new connection, report its answer,
     * serialisation failure or error, and exit without the parent's shutdown.
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
     * Whether the error is a PostgreSQL serialisation failure (40001).
     *
     * On MySQL 40001 is a deadlock; Laravel wraps it in `DeadlockException`
     * inside a transaction.
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
     * Issue a linked `sign_in` code for `web` bound to the client's verifier.
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
            trustVersion: $this->redeemed->trust_version,
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
}
