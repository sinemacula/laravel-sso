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
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Races a principal widening against a reservation and an activation; skipped
 * on SQLite and without `pcntl`. Whichever takes the identity's guard first,
 * the other waits on it.
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
     * Bind fresh authentication, an allow-all limiter and a principal scope
     * that reads the file.
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
     * Rows of `[in a transaction, PostgreSQL outcome, MySQL outcome]` of a
     * widening after a reservation.
     *
     * @return iterable<string, array{0: bool, 1: string, 2: string}>
     */
    public static function provideWideningsAfterAReservation(): iterable
    {
        yield 'the widening plainly' => [false, self::WIDENED, self::WIDENED];
        yield 'the widening in its own that read first' => [true, self::SERIALIZATION, self::RETRY];
    }

    /**
     * A widening after a reservation holding the guard deletes it, or fails for
     * a retry.
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
     * A reservation waiting on a widening's guard judges the new principal and
     * reserves nothing.
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
     * Rows of `[activation in a transaction, widening in a transaction,
     * PostgreSQL outcome, MySQL outcome]`.
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
     * A widening after an activation holding the guard suspends the link, or
     * fails for a retry.
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
     * An activation waiting on a widening's guard activates nothing.
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
     * A two-identity widening takes every guard before any connection, so it
     * never deadlocks.
     *
     * @return void
     */
    public function testAWideningOfTwoIdentitiesTakesEveryGuardBeforeAConnection(): void
    {
        $this->requireRacing();
        $this->start();
        $this->answerFromThePrincipal();

        $other = new IdentityReference('App\Models\User', '8');
        $link  = $this->activeDomainLinkOf($other);

        $outcomes = $this->race([
            [function (): string {
                self::await($this->signal('read-1'));

                $this->holdOnceGuardedUntil('widening');

                return $this->outcomeOf($this->complete());
            }, false],
            [function () use ($other): string {
                self::await($this->signal('holding'));

                $this->signalBeforeTheGuard('widening', $this->person);

                DB::connection(StorageConnection::name())->transaction(fn (): int => app(ScopeWidening::class)->widened([$other, $this->person], 'tenant-2', Clients::browser()));

                return self::WIDENED;
            }, false],
        ]);

        self::assertSame([self::COMPLETED, self::WIDENED], $outcomes);
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
        self::assertSame($link->id, Link::query()->sole()->id);
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

        $this->connection->getConnection()->transaction(fn (): int => app(ScopeWidening::class)->widened([$this->person], 'tenant-2', Clients::browser()));
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
     * Report the principal, signalling just before taking the guard the stopped
     * racer holds.
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
     * Report the principal holding the guard, writing it only once the other is
     * about to wait.
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
     * Touch the signal just before this process takes an identity's guard.
     *
     * @param  string  $signal
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return void
     */
    private function signalBeforeTheGuard(string $signal, ?IdentityReference $identity = null): void
    {
        $table  = StorageConnection::table('identity_guards.table');
        $path   = $this->signal($signal);
        $digest = $identity === null ? null : IdentityLock::digest($identity);

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query, array $bindings) use ($table, $path, $digest): void {

            $sql = strtolower($query);

            if (!str_starts_with($sql, 'insert') || !str_contains($sql, $table) || ($digest !== null && !in_array($digest, $bindings, true))) {
                return;
            }

            touch($path);
        });
    }

    /**
     * Once this process holds an identity's guard, signal `holding` just before
     * it locks a connection, and wait for the signal before sending it.
     *
     * @param  string  $signal
     * @return void
     */
    private function holdOnceGuardedUntil(string $signal): void
    {
        $guards      = StorageConnection::table('identity_guards.table');
        $connections = StorageConnection::table('connections.table');
        $holding     = $this->signal('holding');
        $until       = $this->signal($signal);
        $guarded     = false;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query) use ($guards, $connections, $holding, $until, &$guarded): void {

            $sql = strtolower($query);

            if (str_starts_with($sql, 'insert') && str_contains($sql, $guards)) {
                $guarded = true;

                return;
            }

            if (!$guarded || !str_contains($sql, 'for update') || preg_match('/\bfrom\s+["`]?' . preg_quote($connections, '/') . '["`]?\s/', $sql) !== 1) {
                return;
            }

            $guarded = false;

            touch($holding);

            self::await($until);
        });
    }

    /**
     * An active link of the identity by a verified domain, of another subject,
     * in the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function activeDomainLinkOf(IdentityReference $identity): Link
    {
        $key  = new LinkSubject(VerifyingDriver::ISSUER, 'subject-of-' . $identity->id);
        $link = new Link;

        $link->forceFill([
            'connection_id' => $this->connection->id,
            'issuer'        => $key->issuer,
            'subject'       => $key->subject,
            'subject_key'   => $key->key(),
            'identity_type' => $identity->type,
            'identity_id'   => $identity->id,
            'state'         => LinkState::ACTIVE,
            'provenance'    => LinkOrigin::VERIFIED_DOMAIN,
        ])->save();

        return $link;
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
            app(ScopeWidening::class)->widened([$this->person], 'tenant-2', Clients::browser());
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
     * Fork a process per racer and collect what each reported, in order.
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
     * Run the work in a forked process on its own connection, optionally in a
     * `REPEATABLE READ` transaction that read first.
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
        } catch (\Throwable $e) {
            $outcome = match (true) {
                self::changedCandidates($e)      => self::RETRY,
                self::isSerializationFailure($e) => self::SERIALIZATION,
                default                          => 'error: ' . $e::class . ': ' . $e->getMessage(),
            };
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

    /**
     * Whether the error chain holds `LinkCandidatesChanged`, which a nested
     * transaction rethrows as `DeadlockException`.
     *
     * @param  \Throwable  $exception
     * @return bool
     */
    private static function changedCandidates(\Throwable $exception): bool
    {
        for ($error = $exception; $error !== null; $error = $error->getPrevious()) {
            if ($error instanceof LinkCandidatesChanged) {
                return true;
            }
        }

        return false;
    }
}
