<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\Events\TransactionBeginning;
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
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\TestCase;

/**
 * Feature tests for marking the transaction records a failed commit left.
 *
 * Laravel 12 rolls a failed commit back without telling the transactions
 * manager.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StrandedTransactions::class)]
#[CoversClass(SsoServiceProvider::class)]
final class StrandedTransactionsTest extends TestCase
{
    /** @var string The second connection, kept apart from the default. */
    private const string SEPARATE = 'sso_separate_stranded';

    /**
     * The next outermost begin strands the failed commit's records, not its
     * own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOutermostBeginStrandsWhatAFailedCommitLeft(): void
    {
        [$outer, $savepoint] = $this->leaveATransactionBehind();

        self::assertFalse($this->stranded()->isStranded($outer));
        self::assertFalse($this->stranded()->isStranded($savepoint));

        DB::beginTransaction();

        $begun = $this->newestRecord();

        self::assertNotSame($outer, $begun);
        self::assertTrue($this->stranded()->isStranded($outer));
        self::assertTrue($this->stranded()->isStranded($savepoint));
        self::assertFalse($this->stranded()->isStranded($begun));

        DB::commit();

        self::assertCount(0, $this->manager()->getPendingTransactions());
        self::assertCount(0, $this->manager()->getCommittedTransactions());
    }

    /**
     * A savepoint strands nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASavepointStrandsNothing(): void
    {
        DB::beginTransaction();

        $outer = $this->newestRecord();

        DB::beginTransaction();

        $sibling = $this->newestRecord();

        DB::commit();
        DB::beginTransaction();

        $savepoint = $this->newestRecord();

        foreach ([$outer, $sibling, $savepoint] as $record) {
            self::assertFalse($this->stranded()->isStranded($record));
        }

        DB::commit();
        DB::commit();
    }

    /**
     * A transaction run from a commit callback strands nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransactionBegunFromACommitCallbackStrandsNothing(): void
    {
        $begun = null;

        DB::beginTransaction();

        $outer = $this->newestRecord();

        DB::beginTransaction();

        $savepoint = $this->newestRecord();

        DB::commit();

        DB::afterCommit(function () use (&$begun): void {
            DB::transaction(function () use (&$begun): void {
                $begun = $this->newestRecord();
            });
        });

        DB::commit();

        self::assertInstanceOf(DatabaseTransactionRecord::class, $begun);

        foreach ([$outer, $savepoint, $begun] as $record) {
            self::assertFalse($this->stranded()->isStranded($record));
        }
    }

    /**
     * A savepoint opened by a listener on the outermost begin is not stranded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASavepointOfTheTransactionJustBegunIsNotStranded(): void
    {
        [$left] = $this->leaveATransactionBehind();

        $connection = DB::connection();

        $connection->beginTransaction();

        $begun = $this->newestRecord();

        $connection->beginTransaction();

        $savepoint = $this->newestRecord();

        $connection->commit();

        self::assertContains($savepoint, $this->manager()->getCommittedTransactions()->all());

        $this->stranded()->begun(new TransactionBeginning($connection), $this->manager());

        self::assertTrue($this->stranded()->isStranded($left));
        self::assertFalse($this->stranded()->isStranded($begun));
        self::assertFalse($this->stranded()->isStranded($savepoint));

        $connection->rollBack();
    }

    /**
     * Only the connection's own records are stranded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheConnectionsOwnRecordsAreStranded(): void
    {
        $separate = DB::connection(self::SEPARATE);

        $separate->beginTransaction();

        $other = $this->newestRecord();

        [$left] = $this->leaveATransactionBehind();

        DB::beginTransaction();

        $begun = $this->newestRecord();

        self::assertTrue($this->stranded()->isStranded($left));
        self::assertFalse($this->stranded()->isStranded($other));
        self::assertFalse($this->stranded()->isStranded($begun));

        DB::rollBack();
        $separate->rollBack();

        [$left] = $this->leaveATransactionBehind();

        $separate->transaction(static function (): void {});

        self::assertFalse($this->stranded()->isStranded($left));

        DB::transaction(static function (): void {});
    }

    /**
     * Under the testing traits' transactions manager, the failed commit's
     * record is still stranded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTestingManagersRecordsAreAllRead(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app        = $this->app;
        $previous   = $this->manager();
        $manager    = new TestingTransactionsManager([null]);
        $connection = DB::connection();

        $app->instance('db.transactions', $manager);
        $connection->setTransactionManager($manager);

        try {
            $connection->beginTransaction();

            $left = $this->newestRecord();

            $connection->unsetTransactionManager();
            $connection->rollBack();
            $connection->setTransactionManager($manager);

            self::assertSame([$left], $manager->getPendingTransactions()->all());
            self::assertCount(0, $manager->callbackApplicableTransactions());

            $connection->beginTransaction();

            self::assertTrue($this->stranded()->isStranded($left));
            self::assertFalse($this->stranded()->isStranded($this->newestRecord()));

            $connection->rollBack();
        } finally {
            $app->instance('db.transactions', $previous);
            $connection->setTransactionManager($previous);
        }
    }

    /**
     * Under an Octane-style sandbox, the sandbox manager's records are marked
     * and shared.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheListenerMarksTheCurrentContainersRecords(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app        = $this->app;
        $previous   = $this->manager();
        $stranded   = $this->stranded();
        $sandbox    = clone $app;
        $manager    = new DatabaseTransactionsManager;
        $connection = DB::connection();
        $delivered  = new \ArrayObject;

        Event::listen(SsoEvent::class, static function (SsoEvent $event) use ($delivered): void {
            $delivered->append($event);
        });

        // As Octane's CurrentApplication::set() makes a sandbox current.
        $sandbox->instance('app', $sandbox);
        $sandbox->instance(Container::class, $sandbox);
        $sandbox->instance('db.transactions', $manager);
        $connection->setTransactionManager($manager);
        Container::setInstance($sandbox);

        try {
            $connection->beginTransaction();

            $left = $manager->getPendingTransactions()->last();

            $sandbox->make(AfterCommitDispatcher::class)->dispatch(
                new FlowFailed(new EventContext(CarbonImmutable::parse('2026-10-31T12:00:00Z')), Flow::ASSERTION, FailureReason::REPLAYED),
                (string) $connection->getName(),
            );

            $connection->unsetTransactionManager();
            $connection->rollBack();
            $connection->setTransactionManager($manager);

            $connection->beginTransaction();

            self::assertInstanceOf(DatabaseTransactionRecord::class, $left);
            self::assertTrue($stranded->isStranded($left));
            self::assertSame($stranded, $sandbox->make(StrandedTransactions::class));
            self::assertCount(0, $previous->getPendingTransactions());

            $connection->commit();

            self::assertCount(0, $delivered);
        } finally {
            Container::setInstance($app);
            $connection->setTransactionManager($previous);
        }
    }

    /**
     * One instance serves the process and keeps its marks across scoped resets.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOneInstanceServesTheProcess(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app      = $this->app;
        $stranded = $this->stranded();

        [$left] = $this->leaveATransactionBehind();

        DB::beginTransaction();

        $app->forgetScopedInstances();

        self::assertSame($stranded, $this->stranded());
        self::assertTrue($this->stranded()->isStranded($left));

        DB::rollBack();
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
     * Begin a transaction with a committed savepoint, then end it as a failed
     * commit does.
     *
     * @return array{\Illuminate\Database\DatabaseTransactionRecord, \Illuminate\Database\DatabaseTransactionRecord}
     *
     * @throws \Throwable
     */
    private function leaveATransactionBehind(): array
    {
        $manager    = $this->manager();
        $connection = DB::connection();

        $connection->beginTransaction();

        $outer = $this->newestRecord();

        $connection->beginTransaction();

        $savepoint = $this->newestRecord();

        $connection->commit();
        $connection->unsetTransactionManager();

        try {
            $connection->rollBack();
        } finally {
            $connection->setTransactionManager($manager);
        }

        self::assertSame(0, $connection->transactionLevel());
        self::assertContains($outer, $manager->getPendingTransactions()->all());
        self::assertContains($savepoint, $manager->getCommittedTransactions()->all());

        return [$outer, $savepoint];
    }

    /**
     * The record of the transaction begun last.
     *
     * @return \Illuminate\Database\DatabaseTransactionRecord
     */
    private function newestRecord(): DatabaseTransactionRecord
    {
        $record = $this->manager()->getPendingTransactions()->last();

        self::assertInstanceOf(DatabaseTransactionRecord::class, $record);

        return $record;
    }

    /**
     * The transactions manager, as the container gives it.
     *
     * @return \Illuminate\Database\DatabaseTransactionsManager
     */
    private function manager(): DatabaseTransactionsManager
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        /** @var \Illuminate\Database\DatabaseTransactionsManager */
        return $app->make('db.transactions');
    }

    /**
     * The marks, as the container gives them.
     *
     * @return \SineMacula\Laravel\Sso\Events\StrandedTransactions
     */
    private function stranded(): StrandedTransactions
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(StrandedTransactions::class);
    }
}
