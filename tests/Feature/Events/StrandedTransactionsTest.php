<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager as TestingTransactionsManager;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Events\StrandedTransactions;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\TestCase;

/**
 * Feature tests for the marking of the transaction records a failed commit left
 * behind, against real transactions on whichever engine the suite runs on and a
 * second connection: an outermost begin strands every record its connection
 * still holds but its own and the savepoints inside it, a savepoint strands
 * nothing, a transaction begun from a commit callback leaves the committing
 * records alone, another connection's records are never touched, and one
 * instance serves the whole process.
 *
 * The failed commit is reproduced as Laravel 12 leaves it: the database rolls
 * the transaction back, but the transactions manager is never told.
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
     * The next outermost begin on the connection strands the record a failed
     * commit left pending and the savepoint record it staged, and not the
     * record just begun; the records are gone once that transaction commits.
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
     * A savepoint strands nothing: neither the transaction it sits in, nor a
     * savepoint that committed before it, nor itself.
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
     * A transaction begun and committed from a commit callback strands neither
     * the records whose callbacks are running nor its own.
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
     * A savepoint opened and committed by an earlier listener on the beginning
     * of the outermost transaction is that transaction's own, not stranded.
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

        $this->stranded()->begun(new TransactionBeginning($connection));

        self::assertTrue($this->stranded()->isStranded($left));
        self::assertFalse($this->stranded()->isStranded($begun));
        self::assertFalse($this->stranded()->isStranded($savepoint));

        $connection->rollBack();
    }

    /**
     * Only the connection's own records are stranded: a transaction open on
     * another connection keeps its record, and an outermost begin there strands
     * nothing of the default connection.
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
     * Under the transactions manager of Laravel's testing traits, the records
     * it skips by position are read too: a transaction begun after a failed
     * commit strands the record it left, and not its own.
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
     * Without a transactions manager bound, a transaction begins and nothing is
     * marked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNothingIsMarkedWithoutATransactionsManager(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app      = $this->app;
        $previous = $this->manager();

        [$left] = $this->leaveATransactionBehind();

        $app->offsetUnset('db.transactions');

        try {
            DB::beginTransaction();

            self::assertSame(1, DB::transactionLevel());
            self::assertFalse($this->stranded()->isStranded($left));

            DB::rollBack();
        } finally {
            $app->instance('db.transactions', $previous);
        }
    }

    /**
     * One instance serves the process: the same one is resolved every time, and
     * it survives the scoped instances being forgotten between requests and
     * jobs, with its marks.
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
     * Begin an outermost transaction on the default connection with a savepoint
     * that commits inside it, then end it as Laravel 12 ends one whose commit
     * failed: the database rolls it back, but the transactions manager is never
     * told.
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
