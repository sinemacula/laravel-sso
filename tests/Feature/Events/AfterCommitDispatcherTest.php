<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager as TestingTransactionsManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\AfterCommitDispatcher;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\StrandedTransactions;
use Tests\TestCase;

/**
 * Feature tests for the dispatch of package events once the writes that caused
 * them commit, against real transactions on whichever engine the suite runs on,
 * and a second connection: at once outside a transaction, on the commit of the
 * storage connection's transaction, never on its rollback or a savepoint's,
 * whatever another connection's transaction does, nor on a later transaction's
 * commit when its own commit failed; and at once, always, for the synchronous
 * dispatch.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AfterCommitDispatcher::class)]
#[CoversClass(StrandedTransactions::class)]
final class AfterCommitDispatcherTest extends TestCase
{
    /** @var string The second connection, kept apart from the default. */
    private const string SEPARATE = 'sso_separate';

    /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Contracts\SsoEvent> The package events delivered, in order. */
    private \ArrayObject $delivered;

    /**
     * Record every package event delivered.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $delivered = new \ArrayObject;

        Event::listen(SsoEvent::class, static function (SsoEvent $event) use ($delivered): void {
            $delivered->append($event);
        });

        $this->delivered = $delivered;
    }

    /**
     * Outside any transaction, the event is dispatched at once, and a
     * connection named that has not been used is not made to find that out.
     *
     * @return void
     */
    public function testDispatchesAtOnceOutsideATransaction(): void
    {
        $event = self::event();
        $named = self::event(FailureReason::SIGNATURE_INVALID);

        $this->dispatcher()->dispatch($event);
        $this->dispatcher()->dispatch($named, self::SEPARATE);

        self::assertSame([$event, $named], $this->delivered->getArrayCopy());
        self::assertArrayNotHasKey(self::SEPARATE, DB::getConnections());
    }

    /**
     * Inside a transaction on the storage connection, the event waits for it to
     * commit, including an outer one it is nested in, and is dispatched once on
     * that commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWaitsForTheStorageConnectionsTransactionToCommit(): void
    {
        $event = self::event();

        DB::transaction(function () use ($event): void {
            DB::transaction(function () use ($event): void {
                $this->dispatcher()->dispatch($event);
            });

            self::assertCount(0, $this->delivered);
        });

        self::assertSame([$event], $this->delivered->getArrayCopy());
    }

    /**
     * An event dispatched inside a transaction that rolls back is never
     * dispatched, then or later.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNeverDispatchesAfterARollback(): void
    {
        DB::beginTransaction();

        $this->dispatcher()->dispatch(self::event());

        DB::rollBack();

        self::assertCount(0, $this->delivered);

        DB::transaction(static function (): void {});

        self::assertCount(0, $this->delivered);
    }

    /**
     * An event dispatched in a savepoint that rolls back is dropped, while one
     * dispatched in the outer transaction still follows its commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolledBackSavepointDropsOnlyItsEvents(): void
    {
        $kept    = self::event(FailureReason::REPLAYED);
        $dropped = self::event(FailureReason::SIGNATURE_INVALID);

        DB::beginTransaction();

        $this->dispatcher()->dispatch($kept);

        DB::beginTransaction();

        $this->dispatcher()->dispatch($dropped);

        DB::rollBack();
        DB::commit();

        self::assertSame([$kept], $this->delivered->getArrayCopy());
    }

    /**
     * A savepoint nested in others that rolls back drops the events dispatched
     * inside it, those of a savepoint it holds that committed included, and
     * nothing else: the events of the savepoints around it that commit, and of
     * the outer transaction, follow its commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNestedSavepointRollbacksDropOnlyTheirEvents(): void
    {
        $outer  = self::event(FailureReason::REPLAYED);
        $middle = self::event(FailureReason::SIGNATURE_INVALID);
        $after  = self::event(FailureReason::REPLAYED);

        DB::beginTransaction();

        $this->dispatcher()->dispatch($outer);

        DB::beginTransaction();

        $this->dispatcher()->dispatch($middle);

        DB::beginTransaction();

        $this->dispatcher()->dispatch(self::event());

        DB::rollBack();
        DB::commit();

        DB::beginTransaction();

        $this->dispatcher()->dispatch(self::event());

        DB::beginTransaction();

        $this->dispatcher()->dispatch(self::event());

        DB::commit();
        DB::rollBack();

        $this->dispatcher()->dispatch($after);

        self::assertSame(1, DB::transactionLevel());
        self::assertCount(0, $this->delivered);

        DB::commit();

        self::assertCount(3, $this->delivered);

        foreach ([$outer, $middle, $after] as $event) {
            self::assertContains($event, $this->delivered->getArrayCopy());
        }
    }

    /**
     * A callback left pending by an outermost transaction whose commit failed,
     * as Laravel 12 leaves it by not telling its transactions manager, is
     * dropped when the next outermost transaction commits, and only that
     * transaction's own event is dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallbackLeftByAFailedCommitIsDropped(): void
    {
        $kept = self::event(FailureReason::SIGNATURE_INVALID);

        $this->leaveATransactionBehind(self::event());

        DB::transaction(function () use ($kept): void {
            $this->dispatcher()->dispatch($kept);
        });

        self::assertSame([$kept], $this->delivered->getArrayCopy());

        DB::transaction(static function (): void {});

        self::assertSame([$kept], $this->delivered->getArrayCopy());
    }

    /**
     * Outside any transaction, an event is dispatched at once even while the
     * transactions manager still holds a record that a failed commit left on
     * the connection, and is not dispatched again when the next transaction
     * commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDispatchesAtOnceBesideARecordAFailedCommitLeft(): void
    {
        $event = self::event(FailureReason::SIGNATURE_INVALID);

        $this->leaveATransactionBehind(self::event());

        $this->dispatcher()->dispatch($event);

        self::assertSame([$event], $this->delivered->getArrayCopy());

        DB::transaction(static function (): void {});

        self::assertSame([$event], $this->delivered->getArrayCopy());
    }

    /**
     * An earlier callback of the same commit that begins and commits an
     * outermost transaction does not drop the event: it is dispatched once,
     * after that callback.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEarlierCallbacksTransactionDoesNotDropTheEvent(): void
    {
        $event = self::event();

        /** @var \ArrayObject<int, string> $order */
        $order = new \ArrayObject;

        DB::beginTransaction();

        DB::afterCommit(static function () use ($order): void {
            DB::transaction(static function (): void {});

            $order->append('callback');
        });

        $this->dispatcher()->dispatch($event);

        DB::commit();

        self::assertSame(['callback'], $order->getArrayCopy());
        self::assertSame([$event], $this->delivered->getArrayCopy());

        DB::transaction(static function (): void {});

        self::assertSame([$event], $this->delivered->getArrayCopy());
    }

    /**
     * An event dispatched in a transaction a callback of the committing one
     * begins is dispatched once, on that transaction's commit, and each event
     * of the committing transaction, its savepoint's included, once too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallbacksOwnTransactionDispatchesBesideTheCommittingOne(): void
    {
        $outer     = self::event(FailureReason::REPLAYED);
        $savepoint = self::event(FailureReason::SIGNATURE_INVALID);
        $inner     = self::event(FailureReason::REPLAYED);

        DB::beginTransaction();

        DB::afterCommit(function () use ($inner): void {
            DB::transaction(function () use ($inner): void {
                $this->dispatcher()->dispatch($inner);
            });
        });

        $this->dispatcher()->dispatch($outer);

        DB::transaction(function () use ($savepoint): void {
            $this->dispatcher()->dispatch($savepoint);
        });

        DB::commit();

        self::assertCount(3, $this->delivered);

        foreach ([$inner, $outer, $savepoint] as $event) {
            self::assertContains($event, $this->delivered->getArrayCopy());
        }

        DB::transaction(static function (): void {});

        self::assertCount(3, $this->delivered);
    }

    /**
     * After a failed commit, the next transaction's own event is dispatched
     * once though an earlier callback of its commit begins a transaction, and
     * the event the failed commit left is still dropped.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStrandedEventStaysDroppedBesideACallbacksTransaction(): void
    {
        $kept = self::event(FailureReason::SIGNATURE_INVALID);

        $this->leaveATransactionBehind(self::event());

        DB::transaction(function () use ($kept): void {
            DB::afterCommit(static function (): void {
                DB::transaction(static function (): void {});
            });

            $this->dispatcher()->dispatch($kept);
        });

        self::assertSame([$kept], $this->delivered->getArrayCopy());
    }

    /**
     * A transaction on another connection neither delays nor cancels an event
     * for the storage connection, whether it is the only one open or opened
     * inside the storage connection's own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransactionOnAnotherConnectionDoesNotDefer(): void
    {
        $separate = DB::connection(self::SEPARATE);

        $separate->beginTransaction();

        $this->dispatcher()->dispatch(self::event());

        self::assertCount(1, $this->delivered);

        $separate->rollBack();

        self::assertCount(1, $this->delivered);

        DB::beginTransaction();
        $separate->beginTransaction();

        $this->dispatcher()->dispatch(self::event());

        $separate->rollBack();

        self::assertCount(1, $this->delivered);

        DB::commit();

        self::assertCount(2, $this->delivered);
    }

    /**
     * A connection named waits for its own transaction, not the storage
     * connection's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANamedConnectionWaitsForItsOwnTransaction(): void
    {
        $separate = DB::connection(self::SEPARATE);

        DB::beginTransaction();
        $separate->beginTransaction();

        $this->dispatcher()->dispatch(self::event(), self::SEPARATE);

        DB::rollBack();

        self::assertCount(0, $this->delivered);

        $separate->commit();

        self::assertCount(1, $this->delivered);
    }

    /**
     * With no connection named, the event follows the connection
     * `sso.storage.connection` names, and a transaction on the default
     * connection no longer defers it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDefaultConnectionFollowsTheStorageConnection(): void
    {
        config()->set('sso.storage.connection', self::SEPARATE);

        DB::beginTransaction();

        $this->dispatcher()->dispatch(self::event());

        self::assertCount(1, $this->delivered);

        DB::rollBack();

        $separate = DB::connection(self::SEPARATE);

        $separate->beginTransaction();

        $this->dispatcher()->dispatch(self::event());

        self::assertCount(1, $this->delivered);

        $separate->commit();

        self::assertCount(2, $this->delivered);
    }

    /**
     * A storage connection setting that is not a connection name fails closed
     * rather than dispatching on another connection.
     *
     * @return void
     */
    public function testAMalformedStorageConnectionFailsClosed(): void
    {
        config()->set('sso.storage.connection', ['testing']);

        $this->expectException(\InvalidArgumentException::class);

        try {
            $this->dispatcher()->dispatch(self::event());
        } finally {
            self::assertCount(0, $this->delivered);
        }
    }

    /**
     * The synchronous dispatch, for the unlinked-result event, is at once
     * inside a transaction, and stays dispatched when it rolls back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDispatchNowIsImmediateInsideATransaction(): void
    {
        $event = self::event();

        DB::beginTransaction();

        $this->dispatcher()->dispatchNow($event);

        self::assertSame([$event], $this->delivered->getArrayCopy());

        DB::rollBack();

        self::assertSame([$event], $this->delivered->getArrayCopy());
    }

    /**
     * Under the transactions manager of Laravel's testing traits, the
     * transaction wrapping each test never commits, so it does not defer an
     * event; a transaction opened inside it still does, until it commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testIgnoresTheTransactionWrappingATest(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        /** @var \Illuminate\Database\DatabaseTransactionsManager $previous */
        $previous   = $app->make('db.transactions');
        $manager    = new TestingTransactionsManager([null]);
        $connection = DB::connection();

        $app->instance('db.transactions', $manager);
        $connection->setTransactionManager($manager);
        $connection->beginTransaction();

        try {
            $this->dispatcher()->dispatch(self::event());

            self::assertCount(1, $this->delivered);

            DB::beginTransaction();

            $this->dispatcher()->dispatch(self::event());

            self::assertCount(1, $this->delivered);

            DB::commit();

            self::assertCount(2, $this->delivered);

            DB::beginTransaction();

            DB::afterCommit(static function (): void {
                DB::transaction(static function (): void {});
            });

            $this->dispatcher()->dispatch(self::event());

            DB::commit();

            self::assertCount(3, $this->delivered);
        } finally {
            $connection->rollBack();
            $app->instance('db.transactions', $previous);
            $connection->setTransactionManager($previous);
        }
    }

    /**
     * Without a transactions manager, nothing can be deferred, so the event is
     * dispatched at once even inside a transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDispatchesAtOnceWithoutATransactionsManager(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app      = $this->app;
        $previous = $app->make('db.transactions');

        DB::beginTransaction();

        $app->offsetUnset('db.transactions');

        try {
            $this->dispatcher()->dispatch(self::event());

            self::assertCount(1, $this->delivered);
        } finally {
            $app->instance('db.transactions', $previous);

            DB::rollBack();
        }
    }

    /**
     * The dispatcher bound when the transaction commits receives the event, not
     * the one bound when it was scheduled, so a fake made in between sees it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDispatcherIsResolvedWhenTheEventIsDispatched(): void
    {
        DB::beginTransaction();

        $this->dispatcher()->dispatch(self::event());

        $fake = Event::fake();

        DB::commit();

        $fake->assertDispatched(FlowFailed::class);

        self::assertCount(0, $this->delivered);
    }

    /**
     * A listener's exception propagates from the commit that dispatched the
     * event, as it does from Laravel's dispatcher.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAListenersExceptionPropagates(): void
    {
        Event::listen(FlowFailed::class, static function (): void {
            throw new \RuntimeException('Listener failed.');
        });

        DB::beginTransaction();

        $this->dispatcher()->dispatch(self::event());

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Listener failed.');

        DB::commit();
    }

    /**
     * Add the second connection.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('database.connections.' . self::SEPARATE, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
    }

    /**
     * Dispatch the event inside an outermost transaction on the default
     * connection, then end it as Laravel 12 ends one whose commit failed: the
     * database rolls it back, but the transactions manager is never told, so
     * its record, and the event's callback, stay pending.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @return void
     *
     * @throws \Throwable
     */
    private function leaveATransactionBehind(SsoEvent $event): void
    {
        /** @var \Illuminate\Database\DatabaseTransactionsManager $manager */
        $manager    = app('db.transactions');
        $connection = DB::connection();

        $connection->beginTransaction();

        $this->dispatcher()->dispatch($event);

        $connection->unsetTransactionManager();

        try {
            $connection->rollBack();
        } finally {
            $connection->setTransactionManager($manager);
        }

        self::assertSame(0, $connection->transactionLevel());
        self::assertCount(1, $manager->getPendingTransactions());
        self::assertCount(0, $this->delivered);
    }

    /**
     * Resolve the dispatcher from the container, as the package does.
     *
     * @return \SineMacula\Laravel\Sso\Events\AfterCommitDispatcher
     */
    private function dispatcher(): AfterCommitDispatcher
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(AfterCommitDispatcher::class);
    }

    /**
     * A failure event with the reason given.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Sso\Events\FlowFailed
     */
    private static function event(FailureReason $reason = FailureReason::REPLAYED): FlowFailed
    {
        return new FlowFailed(new EventContext(CarbonImmutable::parse('2026-10-31T12:00:00Z')), Flow::ASSERTION, $reason);
    }
}
