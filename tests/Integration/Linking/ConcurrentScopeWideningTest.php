<?php

declare(strict_types = 1);

namespace Tests\Integration\Linking;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Linking\IdentityLock;
use SineMacula\Laravel\Sso\Linking\ReservationActivation;
use SineMacula\Laravel\Sso\Linking\ReservationDiscovery;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Clients;

/**
 * Races a principal widening across processes, each with its own database
 * connection, on PostgreSQL and MySQL (SSO-8.8, `docs/design/linking.md`),
 * against a reservation and against an activation, in both orders, each
 * overlapping: whichever takes the identity's guard first, the other waits on
 * it, so a racing reservation or activation can never slip past the change.
 *
 * The order is fixed by signal files, never by time, and a barrier that times
 * out fails its racer loudly. A racer that must be waiting on the guard signals
 * just before it sends the guard's statement (a `beforeExecuting` callback), so
 * the other goes on only once the two overlap on the guard; a racer that never
 * takes the guard never signals, and the other's barrier fails the test.
 *
 * The principal is a file the racers' `PrincipalScope` answers `outside_tenant`
 * from once it exists. A widening holding the guard writes it only once the
 * other racer is about to take the guard, and then commits, so a reservation or
 * an activation that judged the scope before taking the guard, or took none,
 * would judge it `within_tenant` and slip past. That contract is also where a
 * reservation or an activation holding the guard stops, with its locks held,
 * until the widening is about to take the guard.
 *
 * The widening runs plainly, and inside a `REPEATABLE READ` transaction of its
 * own that read the connection and its links before the race began, and each
 * row pins its exact outcome. Whose snapshot predates the other's commit
 * either:
 *
 * - fails to serialise on the guard on PostgreSQL (SQLSTATE `40001`, walked
 *   through `getPrevious()`), expected only there and only in a transaction; or
 * - on MySQL, where a plain read answers from that snapshot, finds under the
 *   lock a row in a connection it did not lock, and is `LinkCandidatesChanged`,
 *   expected only there and only in a transaction, when the snapshot missed the
 *   row's connection altogether.
 *
 * Either changed nothing, and a retry of the whole transaction reaches the row.
 *
 * A completion is not run inside a caller's transaction: its consumption
 * commits before validation, by design. An activation runs plainly, and inside
 * such a transaction of its own. Skipped on SQLite and without `pcntl`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ScopeWidening::class)]
#[CoversClass(IdentityLock::class)]
#[CoversClass(ReservationActivation::class)]
#[CoversClass(ReservationDiscovery::class)]
final class ConcurrentScopeWideningTest extends LinkingTestCase
{
    /** @var float Seconds a racer waits for the other's signal before it gives up. */
    private const float SIGNAL_SECONDS = 15.0;

    /** @var string What a widening that committed reports. */
    private const string WIDENED = 'widened';

    /** @var string What a racer that failed to serialise reports. */
    private const string SERIALIZATION = 'serialization';

    /** @var string What a widening refused for a whole retry reports. */
    private const string RETRY = 'retry';

    /** @var string What a completion that issued its code reports. */
    private const string COMPLETED = 'completed:-';

    /** @var string What a completion that reserved nothing reports. */
    private const string UNLINKED = 'failed:unlinked';

    /** @var string What a redemption that succeeded reports. */
    private const string REDEEMED = 'redeemed';

    /** @var string What a redemption of a withdrawn reservation reports. */
    private const string INVALID = 'refused:reservation_invalid';

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /**
     * Bind fresh authentication, a limiter that allows every attempt, and the
     * principal scope that reads the file, and make the directory the processes
     * report in.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->outcomes = sys_get_temp_dir() . '/widening-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);

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
    }

    /**
     * Remove this test's signals and outcomes.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (glob($this->outcomes . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->outcomes);

        parent::tearDown();
    }

    /**
     * Rows of `[whether the widening runs inside its own transaction that read
     * first, how it ends on PostgreSQL, how it ends on MySQL]`, a reservation
     * holding the guard: in a transaction, its snapshot misses the reservation
     * and its connection, so on PostgreSQL its guard fails to serialise, and on
     * MySQL its locking read finds a row in a connection it did not lock.
     *
     * @return iterable<string, array{0: bool, 1: string, 2: string}>
     */
    public static function provideWideningsAfterAReservation(): iterable
    {
        yield 'the widening plainly' => [false, self::WIDENED, self::WIDENED];
        yield 'the widening in its own that read first' => [true, self::SERIALIZATION, self::RETRY];
    }

    /**
     * A reservation holding the guard: the widening waits for it, then finds
     * the row and deletes it, so no reservation survives; or, exactly where the
     * row expects it, it failed to serialise or was refused for a retry, which
     * reaches it.
     *
     * @param  bool  $inTransaction
     * @param  string  $onPostgres
     * @param  string  $onMysql
     * @return void
     */
    #[DataProvider('provideWideningsAfterAReservation')]
    public function testAReservationHoldingTheGuardThenAWidening(bool $inTransaction, string $onPostgres, string $onMysql): void
    {
        $this->requireRacing();
        $this->start();
        $this->stopInTheScope();

        $outcomes = $this->race([
            [function (): string {
                self::await($this->signal('read-1'));

                return $this->outcomeOf($this->complete());
            }, false],
            [fn (): string => $this->widenOnceStopped(), $inTransaction],
        ]);

        self::assertSame(self::COMPLETED, $outcomes[0], implode(', ', $outcomes));
        $this->assertWideningFinds($outcomes[1], $this->onThisEngine($onPostgres, $onMysql), LinkState::RESERVED);

        self::assertSame(0, Link::query()->count());
    }

    /**
     * Rows of `[whether the widening runs inside its own transaction that read
     * first]`.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideWidenings(): iterable
    {
        yield 'the widening plainly' => [false];
        yield 'the widening in its own that read first' => [true];
    }

    /**
     * A widening holding the guard: the reservation reaches the guard while the
     * widening holds it, and only then is the principal written and the
     * widening committed, so the reservation judges the principal under the
     * guard and reserves nothing. A reservation that judged before the guard,
     * or took none, would reserve, or never signal and time the widening out.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideWidenings')]
    public function testAWideningHoldingTheGuardThenAReservation(bool $inTransaction): void
    {
        $this->requireRacing();
        $this->start();
        $this->answerFromThePrincipal();

        $outcomes = $this->race([
            [function (): string {
                self::await($this->signal('read-1'));
                self::await($this->signal('holding'));

                $this->signalBeforeTheGuard('acquiring');

                return $this->outcomeOf($this->complete());
            }, false],
            [fn (): string => $this->widenHoldingUntil('acquiring'), $inTransaction],
        ]);

        self::assertSame([self::UNLINKED, self::WIDENED], $outcomes);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Rows of `[whether the activation runs in its own transaction that read
     * first, whether the widening does, how the widening ends on PostgreSQL,
     * how on MySQL]`, an activation holding the guard: in a transaction, the
     * widening's snapshot holds the reservation, so on PostgreSQL its guard,
     * written since, fails to serialise, and on MySQL it locks the
     * reservation's connection and finds the link active.
     *
     * @return iterable<string, array{0: bool, 1: bool, 2: string, 3: string}>
     */
    public static function provideWideningsAfterAnActivation(): iterable
    {
        yield 'both plainly' => [false, false, self::WIDENED, self::WIDENED];
        yield 'the activation in its own that read first' => [true, false, self::WIDENED, self::WIDENED];
        yield 'the widening in its own that read first' => [false, true, self::SERIALIZATION, self::WIDENED];
    }

    /**
     * An activation holding the guard: the widening waits for it, then finds
     * the link it made and suspends it; or, exactly where the row expects it,
     * it failed to serialise, and a retry reaches it.
     *
     * @param  bool  $activationInTransaction
     * @param  bool  $wideningInTransaction
     * @param  string  $onPostgres
     * @param  string  $onMysql
     * @return void
     */
    #[DataProvider('provideWideningsAfterAnActivation')]
    public function testAnActivationHoldingTheGuardThenAWidening(bool $activationInTransaction, bool $wideningInTransaction, string $onPostgres, string $onMysql): void
    {
        $this->requireRacing();

        [$code, $verifier] = $this->reserved();

        $this->stopInTheScope();

        $outcomes = $this->race([
            [function () use ($code, $verifier): string {
                self::await($this->signal('read-1'));

                return $this->redemption($code, $verifier);
            }, $activationInTransaction],
            [fn (): string => $this->widenOnceStopped(), $wideningInTransaction],
        ]);

        self::assertSame(self::REDEEMED, $outcomes[0], implode(', ', $outcomes));
        $this->assertWideningFinds($outcomes[1], $this->onThisEngine($onPostgres, $onMysql), LinkState::ACTIVE);

        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
    }

    /**
     * Rows of `[whether the activation runs in its own transaction that read
     * first, whether the widening does]`.
     *
     * @return iterable<string, array{0: bool, 1: bool}>
     */
    public static function provideTransactions(): iterable
    {
        yield 'both plainly' => [false, false];
        yield 'the activation in its own that read first' => [true, false];
        yield 'the widening in its own that read first' => [false, true];
    }

    /**
     * A widening holding the guard: the activation reaches the guard while the
     * widening holds it, and only then is the principal written and the
     * widening committed, so the activation finds no reservation and activates
     * nothing, or it failed to serialise on the guard. One that took no guard
     * never signals, and times the widening out.
     *
     * @param  bool  $activationInTransaction
     * @param  bool  $wideningInTransaction
     * @return void
     */
    #[DataProvider('provideTransactions')]
    public function testAWideningHoldingTheGuardThenAnActivation(bool $activationInTransaction, bool $wideningInTransaction): void
    {
        $this->requireRacing();

        [$code, $verifier] = $this->reserved();

        $this->answerFromThePrincipal();

        $outcomes = $this->race([
            [function () use ($code, $verifier): string {
                self::await($this->signal('read-1'));
                self::await($this->signal('holding'));

                $this->signalBeforeTheGuard('acquiring');

                return $this->redemption($code, $verifier);
            }, $activationInTransaction],
            [fn (): string => $this->widenHoldingUntil('acquiring'), $wideningInTransaction],
        ]);

        $failsToSerialize = $activationInTransaction && DB::connection(StorageConnection::name())->getDriverName() === 'pgsql';

        self::assertSame([$failsToSerialize ? self::SERIALIZATION : self::INVALID, self::WIDENED], $outcomes);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Assert the widening that came second ended exactly as expected, and, when
     * it was refused, that it changed nothing, and retry it.
     *
     * @param  string  $outcome
     * @param  string  $expected
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $unchanged
     * @return void
     */
    private function assertWideningFinds(string $outcome, string $expected, LinkState $unchanged): void
    {
        self::assertSame($expected, $outcome);

        if ($outcome === self::WIDENED) {
            return;
        }

        self::assertSame($unchanged, Link::query()->sole()->state);

        $this->connection->getConnection()->transaction(fn (): int => app(ScopeWidening::class)->widened($this->person, 'tenant-2', Clients::browser()));
    }

    /**
     * Of the two outcomes, the one expected on this engine.
     *
     * @param  string  $onPostgres
     * @param  string  $onMysql
     * @return string
     */
    private function onThisEngine(string $onPostgres, string $onMysql): string
    {
        return DB::connection(StorageConnection::name())->getDriverName() === 'pgsql' ? $onPostgres : $onMysql;
    }

    /**
     * Complete an eligible flow in this process, and answer its code and
     * verifier.
     *
     * @return array{0: string, 1: string}
     */
    private function reserved(): array
    {
        $start      = $this->start();
        $completion = $this->complete();

        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);

        return [(string) $completion->handoff?->code->reveal(), (string) $start->verifier?->reveal()];
    }

    /**
     * Report the principal as a principal mutation does, once the racer holding
     * the guard has stopped in its scope contract: signal just before sending
     * the guard's statement, so that racer goes on only once this one is about
     * to wait on the guard.
     *
     * @return string
     */
    private function widenOnceStopped(): string
    {
        self::await($this->signal('stopped'));

        $this->signalBeforeTheGuard('widening');

        return $this->widen(static function (): void {});
    }

    /**
     * Report the principal as a principal mutation does, holding the guard:
     * signal that it holds it, wait until the other is about to take it, and
     * only then write the principal and commit.
     *
     * @param  string  $signal
     * @return string
     */
    private function widenHoldingUntil(string $signal): string
    {
        return $this->widen(function () use ($signal): void {
            touch($this->signal('holding'));

            self::await($this->signal($signal));

            touch($this->signal('principal'));
        });
    }

    /**
     * Touch the signal just before this process sends the statement that takes
     * an identity's guard, on its own connection.
     *
     * @param  string  $signal
     * @return void
     */
    private function signalBeforeTheGuard(string $signal): void
    {
        $table = StorageConnection::table('identity_guards.table');
        $path  = $this->signal($signal);

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query) use ($table, $path): void {

            $sql = strtolower($query);

            if (!str_starts_with($sql, 'insert') || !str_contains($sql, $table)) {
                return;
            }

            touch($path);
        });
    }

    /**
     * The principal mutation: `widened()` first, then what it does under the
     * guard, in its one transaction; say how it ended.
     *
     * @param  \Closure(): void  $underTheGuard
     * @return string
     */
    private function widen(\Closure $underTheGuard): string
    {
        DB::connection(StorageConnection::name())->transaction(function () use ($underTheGuard): void {
            app(ScopeWidening::class)->widened($this->person, 'tenant-2', Clients::browser());
            $underTheGuard();
        });

        return self::WIDENED;
    }

    /**
     * Redeem the code in a transaction, and say how it ended. Inside a racer's
     * own transaction, it is a savepoint.
     *
     * @param  string  $code
     * @param  string  $verifier
     * @return string
     */
    private function redemption(string $code, string $verifier): string
    {
        $admit  = fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $this->connection->id, $code, $verifier, Clients::browser());
        $answer = DB::connection(StorageConnection::name())->transaction($admit);

        return $answer->isRedeemed() ? self::REDEEMED : 'refused:' . $answer->reason?->value;
    }

    /**
     * Bind a principal scope that answers `within_tenant`, stopping with the
     * racer's locks held until the widening has started.
     *
     * @return void
     */
    private function stopInTheScope(): void
    {
        $this->bindScope(function (): void {
            touch($this->signal('stopped'));

            self::await($this->signal('widening'));
        });
    }

    /**
     * Bind a principal scope that answers from the principal alone.
     *
     * @return void
     */
    private function answerFromThePrincipal(): void
    {
        $this->bindScope(static function (): void {});
    }

    /**
     * Bind a principal scope that first runs the closure, then answers
     * `outside_tenant` once the principal has been written.
     *
     * @param  \Closure(): void  $then
     * @return void
     */
    private function bindScope(\Closure $then): void
    {
        $this->app?->instance(PrincipalScope::class, new readonly class ($then, $this->signal('principal')) implements PrincipalScope {
            /**
             * Constructor.
             *
             * @param  \Closure(): void  $then
             * @param  string  $principal
             */
            public function __construct(

                /** What it does each time it is asked. */
                private \Closure $then,

                /** The file that exists once the principal is written. */
                private string $principal,
            ) {}

            /**
             * Run the closure, and answer from the principal.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $tenantId
             * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
             */
            #[\Override]
            public function judge(IdentityReference $identity, string $tenantId): ScopeVerdict
            {
                unset($identity, $tenantId);

                ($this->then)();

                clearstatcache(true, $this->principal);

                return file_exists($this->principal) ? ScopeVerdict::OUTSIDE_TENANT : ScopeVerdict::WITHIN_TENANT;
            }
        });
    }

    /**
     * How the completion ended.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @return string
     */
    private function outcomeOf(CompletionResult $result): string
    {
        return sprintf('%s:%s', $result->status->value, $result->reason->value ?? '-');
    }

    /**
     * Skip where processes cannot share the database.
     *
     * @return void
     */
    private function requireRacing(): void
    {
        if (DB::connection()->getDriverName() !== 'sqlite' && function_exists('pcntl_fork')) {
            return;
        }

        self::markTestSkipped('Racing processes need a shared database server and pcntl.');
    }

    /**
     * Fork a process for each racer, on a connection of its own, plain or
     * inside a transaction of its own, and collect what each reported, in
     * order.
     *
     * @param  list<array{0: \Closure(): string, 1: bool}>  $racers
     * @return list<string>
     */
    private function race(array $racers): array
    {
        DB::disconnect();

        $pids = [];

        foreach ($racers as $process => [$work, $inTransaction]) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $work, $inTransaction);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        $outcomes = [];

        foreach (array_keys($racers) as $process) {
            $outcomes[] = (string) file_get_contents($this->signal("outcome-{$process}"));
        }

        return $outcomes;
    }

    /**
     * In a forked process: open a connection of its own; inside a transaction,
     * open one at `REPEATABLE READ` and read the connection and its links;
     * signal it has read; do its work; commit; report; and end without running
     * the parent's shutdown, which rolls back anything refused for a retry.
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
                Link::query()->where('connection_id', $this->connection->id)->get();
            }

            touch($this->signal("read-{$process}"));

            $outcome = $work();

            if ($inTransaction) {
                $database->commit();
            }
        } catch (LinkCandidatesChanged) {
            $outcome = self::RETRY;
        } catch (\Throwable $e) {
            $outcome = self::isSerializationFailure($e) ? self::SERIALIZATION : 'error: ' . $e::class . ': ' . $e->getMessage();
        }

        file_put_contents($this->signal("outcome-{$process}"), $outcome);
        touch($this->signal("done-{$process}"));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * The path of a signal file of this test.
     *
     * @param  string  $name
     * @return string
     */
    private function signal(string $name): string
    {
        return "{$this->outcomes}/{$name}";
    }

    /**
     * The statement that makes this session's transactions `REPEATABLE READ`.
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
     * when it never appears.
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
            if ($error instanceof QueryException && (string) $error->getCode() === '40001') {
                return DB::connection()->getDriverName() === 'pgsql';
            }
        }

        return false;
    }
}
