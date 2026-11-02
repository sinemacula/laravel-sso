<?php

declare(strict_types = 1);

namespace Tests\Integration\Linking;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\DomainLinkEligibility;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Races a reservation across processes, each with its own database connection,
 * on PostgreSQL and MySQL (SSO-8.8, SSO-8.4, SSO-11.5), with signal files that
 * fail loudly on a timeout, never timing, against each change that takes away
 * what it stands on: a domain withdrawn, a protocol trust change, a linking
 * settings change; against another reservation for one subject, and for one
 * identity under a limit of one; and against an explicit link.
 *
 * A change runs plainly, and inside a `REPEATABLE READ` transaction of its own
 * that read the connection and its links before the race began, in two orders:
 *
 * - while the completion is held once validated, so the reservation finds the
 *   change under the lock and reserves nothing;
 * - after the completion committed its reservation, so the change must delete
 *   it. A change whose snapshot predates the reservation fails to serialise on
 *   PostgreSQL (SQLSTATE `40001`), which raising `links_version` on creation
 *   guarantees, and is accepted only there and only inside a transaction: it
 *   changed nothing, so nothing is missed. No reservation survives a committed
 *   withdrawal.
 *
 * A completion is not run inside a caller's transaction: its consumption
 * commits before validation, by design. Skipped on SQLite and without `pcntl`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainLinkEligibility::class)]
#[CoversClass(LinkReservations::class)]
#[CoversClass(ReservationWithdrawal::class)]
#[CoversClass(LinkStore::class)]
#[CoversClass(LinkingPolicyService::class)]
final class ConcurrentReservationTest extends LinkingTestCase
{
    /** @var float Seconds a racer waits for the other's signal before it gives up. */
    private const float SIGNAL_SECONDS = 10.0;

    /** @var string What a change that committed reports. */
    private const string CHANGED = 'changed';

    /** @var string What a change that failed to serialise reports. */
    private const string SERIALIZATION = 'serialization';

    /** @var string What a completion that issued its code reports. */
    private const string COMPLETED = 'completed:-';

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /** @var list<string> What the last race's racers reported. */
    private array $reported = [];

    /**
     * Bind fresh authentication, and make the directory the processes report
     * in.
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

        $this->outcomes = sys_get_temp_dir() . '/reservation-race-' . bin2hex(random_bytes(8));

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
     * Rows of
     * `[whether the change runs inside its own transaction that read first]`.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideTransactions(): iterable
    {
        yield 'plainly' => [false];
        yield 'inside its own transaction that read first' => [true];
    }

    /**
     * A domain withdrawn while the completion is held reserves nothing.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideTransactions')]
    public function testADomainWithdrawnDuringACompletionReservesNothing(bool $inTransaction): void
    {
        $this->assertHeldCompletionFindsTheChange(fn (): string => $this->withdrawDomain(), $inTransaction, 'failed:unlinked');
    }

    /**
     * A domain withdrawn after the reservation deletes it, or fails to
     * serialise.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideTransactions')]
    public function testADomainWithdrawnAfterAReservationDeletesIt(bool $inTransaction): void
    {
        $this->assertChangeFindsTheReservation(fn (): string => $this->withdrawDomain(), $inTransaction);
    }

    /**
     * A trust change while the completion is held refuses it; a change whose
     * snapshot predates the consumption that voids its request fails to
     * serialise, changing nothing.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideTransactions')]
    public function testATrustChangeDuringACompletionRefusesIt(bool $inTransaction): void
    {
        $this->assertHeldCompletionFindsTheChange(fn (): string => $this->changeTrust(), $inTransaction, 'failed:connection_unavailable');
    }

    /**
     * A trust change after the reservation deletes it, or fails to serialise.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideTransactions')]
    public function testATrustChangeAfterAReservationDeletesIt(bool $inTransaction): void
    {
        $this->assertChangeFindsTheReservation(fn (): string => $this->changeTrust(), $inTransaction);
    }

    /**
     * A linking settings change while the completion is held moves the linking
     * version, so the evidence reserves nothing.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideTransactions')]
    public function testASettingsChangeDuringACompletionReservesNothing(bool $inTransaction): void
    {
        $this->assertHeldCompletionFindsTheChange(fn (): string => $this->changeSettings(), $inTransaction, 'failed:unlinked');
        $this->assertLinkingVersionFollowsTheRace();
    }

    /**
     * A linking settings change after the reservation deletes it, or fails to
     * serialise.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideTransactions')]
    public function testASettingsChangeAfterAReservationDeletesIt(bool $inTransaction): void
    {
        $this->assertChangeFindsTheReservation(fn (): string => $this->changeSettings(), $inTransaction);
        $this->assertLinkingVersionFollowsTheRace();
    }

    /**
     * Two completions of one subject: exactly one reserves, and the other is
     * `link_reserved`, whichever goes first.
     *
     * @return void
     */
    public function testTwoReservationsForOneSubject(): void
    {
        $this->requireRacing();

        $states = $this->startedStates();

        $outcomes = $this->race([
            [fn (): string => $this->afterSignal('read-1', $states[0]), false],
            [fn (): string => $this->afterSignal('read-0', $states[1]), false],
        ]);

        sort($outcomes);

        self::assertSame([self::COMPLETED, 'failed:link_reserved'], $outcomes);
        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
        self::assertSame(1, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
    }

    /**
     * Two subjects for one identity under a limit of one: exactly one reserves,
     * and the other, whichever it is, holds nothing and goes on unlinked.
     *
     * @return void
     */
    public function testTwoReservationsForOneIdentityWithDifferentSubjects(): void
    {
        $this->requireRacing();

        $states = $this->startedStates();

        $outcomes = $this->race([
            [function () use ($states): string {
                $this->verifying->claims = $this->claimsOfSubject('subject-0');

                return $this->afterSignal('read-1', $states[0]);
            }, false],
            [function () use ($states): string {
                $this->verifying->claims = $this->claimsOfSubject('subject-1');

                return $this->afterSignal('read-0', $states[1]);
            }, false],
        ]);

        sort($outcomes);

        self::assertSame([self::COMPLETED, 'failed:unlinked'], $outcomes);
        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
    }

    /**
     * An explicit link after the reservation is refused, under the uniqueness
     * the reservation holds, or fails to serialise, changing nothing: the
     * reservation stands and the subject is linked to nobody else.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideTransactions')]
    public function testAnExplicitLinkAfterAReservationIsRefused(bool $inTransaction): void
    {
        $this->requireRacing();
        $this->start();

        $outcomes = $this->race([
            [function (): string {
                self::await($this->signal('read-1'));

                return $this->outcomeOf($this->complete());
            }, false],
            [function (): string {
                self::await($this->signal('done-0'));

                return $this->explicitLink();
            }, $inTransaction],
        ]);

        self::assertSame(self::COMPLETED, $outcomes[0]);
        self::assertSame($this->isSerializing($inTransaction) ? self::SERIALIZATION : 'refused:subject_already_linked', $outcomes[1]);
        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
        self::assertSame($this->person->id, Link::query()->sole()->identity_id);
    }

    /**
     * A reservation after an explicit link finds it, and resolves to it:
     * nothing is reserved.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideTransactions')]
    public function testAReservationAfterAnExplicitLinkFindsIt(bool $inTransaction): void
    {
        $this->requireRacing();
        $this->start();

        $outcomes = $this->race([
            [function (): string {
                self::await($this->signal('done-1'));

                return $this->outcomeOf($this->complete());
            }, false],
            [fn (): string => $this->explicitLink(), $inTransaction],
        ]);

        self::assertSame([self::COMPLETED, 'created'], $outcomes);

        $row = Link::query()->sole();

        self::assertSame(LinkState::ACTIVE, $row->state);
        self::assertSame('explicit', $row->identity_id);
        self::assertSame(LinkOrigin::LINK_PURPOSE, $row->provenance);
    }

    /**
     * Race a completion held once validated against the change, and assert it
     * refused as given with no reservation, unless the change failed to
     * serialise, which is accepted only on PostgreSQL inside a transaction, and
     * changed nothing, so the completion reserved.
     *
     * @param  \Closure(): string  $change
     * @param  bool  $inTransaction
     * @param  string  $refused
     * @return void
     */
    private function assertHeldCompletionFindsTheChange(\Closure $change, bool $inTransaction, string $refused): void
    {
        $this->requireRacing();
        $this->start();

        $outcomes = $this->race([
            [function (): string {
                self::await($this->signal('read-1'));

                $this->verifying->onComplete = function (): void {
                    touch($this->signal('validated'));
                    self::await($this->signal('done-1'));
                };

                return $this->outcomeOf($this->complete());
            }, false],
            [function () use ($change): string {
                self::await($this->signal('validated'));

                return $change();
            }, $inTransaction],
        ]);

        if ($outcomes[1] === self::SERIALIZATION) {
            self::assertTrue($this->isSerializing($inTransaction), implode(', ', $outcomes));
            self::assertSame(self::COMPLETED, $outcomes[0]);
            self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);

            return;
        }

        self::assertSame([$refused, self::CHANGED], $outcomes);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Race a change whose snapshot, in a transaction, predates the reservation
     * against the completion that makes it, and assert no reservation survives
     * a committed change, and that one predating it fails to serialise rather
     * than miss it.
     *
     * @param  \Closure(): string  $change
     * @param  bool  $inTransaction
     * @return void
     */
    private function assertChangeFindsTheReservation(\Closure $change, bool $inTransaction): void
    {
        $this->requireRacing();
        $this->start();

        $outcomes = $this->race([
            [function (): string {
                self::await($this->signal('read-1'));

                return $this->outcomeOf($this->complete());
            }, false],
            [function () use ($change): string {
                self::await($this->signal('done-0'));

                return $change();
            }, $inTransaction],
        ]);

        if ($this->isSerializing($inTransaction)) {
            self::assertSame([self::COMPLETED, self::SERIALIZATION], $outcomes);
            self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);

            return;
        }

        self::assertSame([self::COMPLETED, self::CHANGED], $outcomes);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Assert the linking version moved by exactly one when the change committed
     * and not at all when it failed to serialise, so a change of nothing can
     * never pass as a change.
     *
     * @return void
     */
    private function assertLinkingVersionFollowsTheRace(): void
    {
        $version = Connection::query()->whereKey($this->connection->id)->sole()->linking_version;

        self::assertSame(in_array(self::CHANGED, $this->reported, true) ? 1 : 0, $version, implode(', ', $this->reported));
    }

    /**
     * Whether a change in such a transaction whose snapshot predates another's
     * commit fails to serialise here.
     *
     * @param  bool  $inTransaction
     * @return bool
     */
    private function isSerializing(bool $inTransaction): bool
    {
        return $inTransaction && DB::connection(StorageConnection::name())->getDriverName() === 'pgsql';
    }

    /**
     * Remove the domain's claim.
     *
     * @return string
     */
    private function withdrawDomain(): string
    {
        return app(DomainService::class)->remove('tenant-1', $this->connection->id, 'example.com')->isChanged() ? self::CHANGED : 'refused';
    }

    /**
     * Make a protocol trust change, in its own transaction.
     *
     * @return string
     */
    private function changeTrust(): string
    {
        DB::connection(StorageConnection::name())->transaction(function (): void {

            /** @var \SineMacula\Laravel\Sso\Models\Connection $locked */
            $locked = Connection::query()->useWritePdo()->lockForUpdate()->whereKey($this->connection->id)->first();

            app(InFlightVoider::class)->voidFor($locked);
        });

        return self::CHANGED;
    }

    /**
     * Change the linking settings.
     *
     * @return string
     */
    private function changeSettings(): string
    {
        return app(LinkingPolicyService::class)->change('tenant-1', $this->connection->id, ['organization_value' => 'changed.example'])->isChanged() ? self::CHANGED : 'refused';
    }

    /**
     * Make an explicit link of the subject, to another identity.
     *
     * @return string
     */
    private function explicitLink(): string
    {
        $subject  = new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT);
        $creation = app(LinkStore::class)->create($this->connection, $subject, new IdentityReference('App\Models\User', 'explicit'), LinkOrigin::LINK_PURPOSE);

        return $creation->isCreated() ? 'created' : 'refused:' . $creation->reason()?->value;
    }

    /**
     * Start two flows and answer the state of each.
     *
     * @return array{0: string, 1: string}
     */
    private function startedStates(): array
    {
        $this->start();

        $first = $this->starting->lastStart()->state->reveal();

        $this->start();

        return [$first, $this->starting->lastStart()->state->reveal()];
    }

    /**
     * Once the other is ready, complete the flow of the state.
     *
     * @param  string  $signal
     * @param  string  $state
     * @return string
     */
    private function afterSignal(string $signal, string $state): string
    {
        self::await($this->signal($signal));

        return $this->outcomeOf(app(CompletionService::class)->callback($this->connection->id, new CompletionRequest('GET', 'state=' . rawurlencode($state), [])));
    }

    /**
     * What a driver verifies for the subject.
     *
     * @param  string  $subject
     * @return \SineMacula\Laravel\Sso\Results\VerifiedClaims
     */
    private function claimsOfSubject(string $subject): VerifiedClaims
    {
        return new VerifiedClaims(
            VerifyingDriver::ISSUER,
            $subject,
            null,
            ['mail' => self::EMAIL],
            new AuthenticationContext($this->clock->now()),
            new LinkingEmail(self::EMAIL, LinkingEmailSource::ID_TOKEN),
        );
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

        $this->reported = $outcomes;

        return $outcomes;
    }

    /**
     * In a forked process: open a connection of its own; inside a transaction,
     * open one at `REPEATABLE READ` and read the connection and its links; signal
     * it has read; do its work; commit; report; signal it is done, once its work
     * is committed or refused; and end without running the parent's shutdown.
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
