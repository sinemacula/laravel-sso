<?php

declare(strict_types = 1);

namespace Tests\Integration\Linking;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Linking\ReservationActivation;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Clients;

/**
 * Races an activation across processes; skipped on SQLite and without `pcntl`.
 * A stale snapshot may fail to serialise (`40001`), accepted on PostgreSQL
 * only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReservationActivation::class)]
#[CoversClass(LinkReservations::class)]
#[CoversClass(ReservationWithdrawal::class)]
#[CoversClass(ScopeWidening::class)]
#[CoversClass(LinkStore::class)]
#[CoversClass(LinkingPolicyService::class)]
final class ConcurrentActivationTest extends LinkingTestCase
{
    /** @var float Seconds a racer waits for the other's signal before it gives up. */
    private const float SIGNAL_SECONDS = 10.0;

    /** @var string What a change that committed reports. */
    private const string CHANGED = 'changed';

    /** @var string What a racer that failed to serialise reports. */
    private const string SERIALIZATION = 'serialization';

    /** @var string What a redemption that succeeded reports. */
    private const string REDEEMED = 'redeemed';

    /** @var string What a redemption of a withdrawn reservation reports. */
    private const string INVALID = 'refused:reservation_invalid';

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /** @var string The code of the reservation raced for. */
    private string $code = '';

    /** @var string The code's verifier. */
    private string $verifier = '';

    /** @var list<string> What the last race's racers reported. */
    private array $reported = [];

    /**
     * Bind fresh authentication, a resolver and an allow-all limiter, whose
     * counters a racer would otherwise hold locked.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(DnsResolver::class, new FakeDnsResolver);
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

        $this->outcomes = sys_get_temp_dir() . '/activation-race-' . bin2hex(random_bytes(8));

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
        foreach (glob($this->outcomes . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->outcomes);

        parent::tearDown();
    }

    /**
     * Rows of `[whether the activation runs in a transaction that read first,
     * whether the change does]`.
     *
     * @return iterable<string, array{0: bool, 1: bool}>
     */
    public static function provideTransactions(): iterable
    {
        yield 'both plainly' => [false, false];
        yield 'the activation in its own that read first' => [true, false];
        yield 'the change in its own that read first' => [false, true];
    }

    /**
     * A lapse that commits first leaves the activation nothing to activate.
     *
     * @param  bool  $activationInTransaction
     * @param  bool  $changeInTransaction
     * @return void
     */
    #[DataProvider('provideTransactions')]
    public function testALapseBeforeAnActivation(bool $activationInTransaction, bool $changeInTransaction): void
    {
        $this->assertTheChangeWins(fn (): string => $this->lapse(), $activationInTransaction, $changeInTransaction, true);
    }

    /**
     * An activation that commits first stands; a lapse then finds no
     * reservation, and takes nothing back.
     *
     * @param  bool  $activationInTransaction
     * @param  bool  $changeInTransaction
     * @return void
     */
    #[DataProvider('provideTransactions')]
    public function testAnActivationBeforeALapse(bool $activationInTransaction, bool $changeInTransaction): void
    {
        $this->assertTheActivationWins(fn (): string => $this->lapse(), $activationInTransaction, $changeInTransaction, LinkState::ACTIVE, true);
    }

    /**
     * A settings change that commits first leaves the activation nothing to
     * activate.
     *
     * @param  bool  $activationInTransaction
     * @param  bool  $changeInTransaction
     * @return void
     */
    #[DataProvider('provideTransactions')]
    public function testASettingsChangeBeforeAnActivation(bool $activationInTransaction, bool $changeInTransaction): void
    {
        $this->assertTheChangeWins(fn (): string => $this->changeSettings(), $activationInTransaction, $changeInTransaction);
        $this->assertLinkingVersionFollowsTheRace();
    }

    /**
     * An activation that commits first stands; a settings change then finds no
     * reservation.
     *
     * @param  bool  $activationInTransaction
     * @param  bool  $changeInTransaction
     * @return void
     */
    #[DataProvider('provideTransactions')]
    public function testAnActivationBeforeASettingsChange(bool $activationInTransaction, bool $changeInTransaction): void
    {
        $this->assertTheActivationWins(fn (): string => $this->changeSettings(), $activationInTransaction, $changeInTransaction, LinkState::ACTIVE);
        $this->assertLinkingVersionFollowsTheRace();
    }

    /**
     * A widening that commits first deletes the reservation.
     *
     * @param  bool  $activationInTransaction
     * @param  bool  $changeInTransaction
     * @return void
     */
    #[DataProvider('provideTransactions')]
    public function testAWideningBeforeAnActivation(bool $activationInTransaction, bool $changeInTransaction): void
    {
        $this->assertTheChangeWins(fn (): string => $this->widen(), $activationInTransaction, $changeInTransaction);
    }

    /**
     * A widening after an activation finds the link and suspends it, whatever
     * its snapshot showed, or fails to serialise.
     *
     * @param  bool  $activationInTransaction
     * @param  bool  $changeInTransaction
     * @return void
     */
    #[DataProvider('provideTransactions')]
    public function testAnActivationBeforeAWidening(bool $activationInTransaction, bool $changeInTransaction): void
    {
        $this->assertTheActivationWins(fn (): string => $this->widen(), $activationInTransaction, $changeInTransaction, LinkState::SUSPENDED);
    }

    /**
     * Rows of `[whether each redeems in a transaction that read first]`.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideRedemptions(): iterable
    {
        yield 'each in a transaction of its own' => [false];
        yield 'each in one that read first' => [true];
    }

    /**
     * Two redemptions of one code: exactly one activates, and the other is
     * `replayed`, or fails to serialise.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideRedemptions')]
    public function testTwoRedemptionsOfOneCode(bool $inTransaction): void
    {
        $this->requireRacing();
        $this->reserve();

        $outcomes = $this->race([
            [function (): string {
                self::await($this->signal('read-1'));

                return $this->redemption();
            }, $inTransaction],
            [function (): string {
                self::await($this->signal('read-0'));

                return $this->redemption();
            }, $inTransaction],
        ]);

        $listed = implode(', ', $outcomes);

        self::assertCount(1, array_keys($outcomes, self::REDEEMED, true), $listed);

        $other = $outcomes[0] === self::REDEEMED ? $outcomes[1] : $outcomes[0];

        self::assertContains($other, $this->isSerializing($inTransaction) ? ['refused:replayed', self::SERIALIZATION] : ['refused:replayed'], $listed);
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        self::assertSame($this->person->id, Link::query()->sole()->identity_id);
        self::assertNotNull(HandoffCode::query()->sole()->redeemed_at);
    }

    /**
     * Make the reservation, run the change, then the activation, and assert the
     * activation found nothing to activate, or failed to serialise.
     *
     * @param  \Closure(): string  $change
     * @param  bool  $activationInTransaction
     * @param  bool  $changeInTransaction
     * @param  bool  $lapsing
     * @return void
     */
    private function assertTheChangeWins(\Closure $change, bool $activationInTransaction, bool $changeInTransaction, bool $lapsing = false): void
    {
        $this->requireRacing();
        $this->reserve($lapsing);

        $outcomes = $this->race([
            [function (): string {
                self::await($this->signal('done-1'));

                return $this->redemption();
            }, $activationInTransaction],
            [function () use ($change): string {
                self::await($this->signal('read-0'));

                return $change();
            }, $changeInTransaction],
        ]);

        self::assertSame([$this->isSerializing($activationInTransaction) ? self::SERIALIZATION : self::INVALID, self::CHANGED], $outcomes);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Reserve, activate, then run the change, and assert the link ends as
     * given.
     *
     * @param  \Closure(): string  $change
     * @param  bool  $activationInTransaction
     * @param  bool  $changeInTransaction
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $state
     * @param  bool  $lapsing
     * @return void
     */
    private function assertTheActivationWins(\Closure $change, bool $activationInTransaction, bool $changeInTransaction, LinkState $state, bool $lapsing = false): void
    {
        $this->requireRacing();
        $this->reserve($lapsing);

        $outcomes = $this->race([
            [function (): string {
                self::await($this->signal('read-1'));

                return $this->redemption();
            }, $activationInTransaction],
            [function () use ($change): string {
                self::await($this->signal('done-0'));

                return $change();
            }, $changeInTransaction],
        ]);

        if ($this->isSerializing($changeInTransaction)) {
            self::assertSame([self::REDEEMED, self::SERIALIZATION], $outcomes);
            self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);

            return;
        }

        self::assertSame([self::REDEEMED, self::CHANGED], $outcomes);
        self::assertSame($state, Link::query()->sole()->state);
        self::assertNull(Link::query()->sole()->reservation_id);
    }

    /**
     * Assert the linking version moved by one if the change committed, and not
     * if it failed to serialise.
     *
     * @return void
     */
    private function assertLinkingVersionFollowsTheRace(): void
    {
        $version = Connection::query()->whereKey($this->connection->id)->sole()->linking_version;

        self::assertSame(in_array(self::CHANGED, $this->reported, true) ? 1 : 0, $version, implode(', ', $this->reported));
    }

    /**
     * Whether a racer in such a transaction, whose snapshot predates another's
     * commit, fails to serialise here.
     *
     * @param  bool  $inTransaction
     * @return bool
     */
    private function isSerializing(bool $inTransaction): bool
    {
        return $inTransaction && DB::connection(StorageConnection::name())->getDriverName() === 'pgsql';
    }

    /**
     * Complete an eligible flow in this process, keeping its code and verifier;
     * for a lapse, on a claim whose grace runs out half a minute from now.
     *
     * @param  bool  $lapsing
     * @return void
     */
    private function reserve(bool $lapsing = false): void
    {
        if ($lapsing) {
            $this->domain->forceFill(['lapses_at' => $this->clock->now()->addSeconds(30)])->save();
        }

        $start      = $this->start();
        $completion = $this->complete();

        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);

        $this->code     = (string) $completion->handoff?->code->reveal();
        $this->verifier = (string) $start->verifier?->reveal();
    }

    /**
     * Redeem the code in a transaction, and say how it ended. Inside a racer's
     * own transaction, it is a savepoint.
     *
     * @return string
     */
    private function redemption(): string
    {
        $admit  = fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $this->connection->id, $this->code, $this->verifier, Clients::browser());
        $answer = DB::connection(StorageConnection::name())->transaction($admit);

        return $answer->isRedeemed() ? self::REDEEMED : 'refused:' . $answer->reason?->value;
    }

    /**
     * Lapse the claim, its grace run out in this process.
     *
     * @return string
     */
    private function lapse(): string
    {
        $this->clock->advance(30);

        $claim = Domain::query()->whereKey($this->domain->id)->sole();

        return app(DomainRechecker::class)->recheck($claim, Clients::browser())->outcome === RecheckOutcome::LAPSED ? self::CHANGED : 'skipped';
    }

    /**
     * Change the linking settings.
     *
     * @return string
     */
    private function changeSettings(): string
    {
        return app(LinkingPolicyService::class)->change(
            'tenant-1',
            $this->connection->id,
            ['organization_value' => 'changed.example'],
            Clients::browser(),
        )->isChanged() ? self::CHANGED : 'refused';
    }

    /**
     * Report a principal of another tenant, as a principal mutation does.
     *
     * @return string
     */
    private function widen(): string
    {
        DB::connection(StorageConnection::name())->transaction(function (): void {
            app(ScopeWidening::class)->widened([$this->person], 'tenant-2', Clients::browser());
        });

        return self::CHANGED;
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

        $this->reported = $outcomes;

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
