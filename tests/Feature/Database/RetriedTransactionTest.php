<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Database\Connection;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Database\RetriedTransaction;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use Tests\TestCase;

/**
 * Feature tests for the transaction tried again on a concurrency failure, on
 * every database the suite runs on: a serialisation failure (SQLSTATE `40001`)
 * in a savepoint, which Laravel throws as a `DeadlockException` it does not
 * recognise, is unwrapped and retried; a deadlock is retried by its message as
 * before; every other exception, a `DeadlockException` that does not end in a
 * serialisation failure included, propagates as it is; and an exception after
 * the commit never runs the work again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RetriedTransaction::class)]
final class RetriedTransactionTest extends TestCase
{
    /** @var string What PostgreSQL says when it cannot serialise a statement. */
    private const string SERIALIZATION_FAILURE = 'SQLSTATE[40001]: Serialization failure: 7 ERROR:  could not serialize access due to concurrent update';

    /** @var string What MySQL says when it rolls a transaction back as a deadlock. */
    private const string DEADLOCK = 'Deadlock found when trying to get lock; try restarting transaction';

    /** @var string The table the work writes to. */
    private const string TABLE = 'retried_rows';

    /** @var int How many times the work ran. */
    private int $runs = 0;

    /**
     * Create the table the work writes to.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $schema = $this->database()->getSchemaBuilder();

        $schema->dropIfExists(self::TABLE);
        $schema->create(self::TABLE, static function (Blueprint $table): void {
            $table->integer('run');
        });
    }

    /**
     * Drop the table the work writes to.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->database()->getSchemaBuilder()->dropIfExists(self::TABLE);

        parent::tearDown();
    }

    /**
     * Rows of `[the SQLSTATE as the driver gives it]`.
     *
     * @return iterable<string, array{0: int|string}>
     */
    public static function provideSerializationCodes(): iterable
    {
        yield 'as a string, as PDO gives it' => ['40001'];
        yield 'as a number' => [40001];
    }

    /**
     * A serialisation failure in a savepoint inside the work is retried, and
     * the attempt that goes through answers; what the failed attempt wrote
     * rolled back with it.
     *
     * @param  int|string  $code
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSerializationCodes')]
    public function testASerializationFailureInASavepointIsRetried(int|string $code): void
    {
        $failure = self::failure(self::SERIALIZATION_FAILURE, $code);

        $answer = RetriedTransaction::run($this->database(), function (Connection $connection) use ($failure): string {

            $connection->table(self::TABLE)->insert(['run' => ++$this->runs]);

            if ($this->runs === 1) {
                $connection->transaction(static fn (): never => throw $failure);
            }

            return 'answered';
        }, 3);

        self::assertSame('answered', $answer);
        self::assertSame(2, $this->runs);
        self::assertSame([2], $this->storedRuns());
        self::assertSame(0, $this->database()->transactionLevel());
    }

    /**
     * A serialisation failure at the end of a chain of `DeadlockException`s, as
     * savepoints nested in savepoints throw it, is retried up to the attempts
     * given, and the failure itself propagates from the last.
     *
     * @return void
     */
    public function testTheLastAttemptPropagatesTheSerializationFailureItself(): void
    {
        $failure = self::failure(self::SERIALIZATION_FAILURE, '40001');
        $wrapped = new DeadlockException('outer', 0, new DeadlockException('inner', 0, $failure));

        self::assertSame($failure, $this->failed(static fn (): mixed => throw $wrapped));
        self::assertSame(3, $this->runs);
        self::assertSame(0, $this->database()->transactionLevel());
    }

    /**
     * A deadlock in a savepoint is retried by its message, as Laravel retries
     * it unaided.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeadlockInASavepointIsRetried(): void
    {
        $failure = self::failure(self::DEADLOCK, 'HY000');

        $answer = RetriedTransaction::run($this->database(), function (Connection $connection) use ($failure): int {

            if (++$this->runs === 1) {
                $connection->transaction(static fn (): never => throw $failure);
            }

            return $this->runs;
        }, 3);

        self::assertSame(2, $answer);
    }

    /**
     * Rows of `[what the work throws]`: each the transaction propagates as it
     * is, on its first attempt.
     *
     * @return iterable<string, array{0: \Throwable}>
     */
    public static function provideOtherExceptions(): iterable
    {
        $notDatabase = new \RuntimeException('Not a database error.', 40001);

        yield 'an application exception' => [new \RuntimeException('The work failed.')];
        yield 'a database error' => [self::failure('SQLSTATE[HY000]: General error', 'HY000')];
        yield 'a DeadlockException with no cause' => [new DeadlockException('No cause.')];
        yield 'a DeadlockException ending in another error' => [new DeadlockException('outer', 0, new DeadlockException('inner', 0, $notDatabase))];
        yield 'a DeadlockException ending in another SQLSTATE' => [new DeadlockException('outer', 0, self::failure('SQLSTATE[23505]: Unique violation', '23505'))];
    }

    /**
     * Every other exception propagates as it is, and the work runs once.
     *
     * @param  \Throwable  $thrown
     * @return void
     */
    #[DataProvider('provideOtherExceptions')]
    public function testAnyOtherExceptionPropagatesAsItIs(\Throwable $thrown): void
    {
        self::assertSame($thrown, $this->failed(static fn (): mixed => throw $thrown));
        self::assertSame(1, $this->runs);
        self::assertSame(0, $this->database()->transactionLevel());
    }

    /**
     * Inside the caller's transaction a serialisation failure is never retried
     * in part: it propagates at once, Laravel's `DeadlockException` carrying
     * the failure, and the caller's transaction stays open.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideTheCallersTransactionItPropagates(): void
    {
        $failure  = self::failure(self::SERIALIZATION_FAILURE, '40001');
        $database = $this->database();

        $database->beginTransaction();

        try {
            $thrown = $this->failed(static fn (Connection $connection): mixed => $connection->transaction(static fn (): never => throw $failure));
            $level  = $database->transactionLevel();
        } finally {
            $database->rollBack();
        }

        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertSame($failure, $thrown->getPrevious());
        self::assertSame(1, $level);
        self::assertSame(1, $this->runs);
    }

    /**
     * An exception after the commit, an after-commit callback's, propagates and
     * never runs the work again, however it was caused.
     *
     * @return void
     */
    public function testAnExceptionAfterTheCommitNeverRunsTheWorkAgain(): void
    {
        $failure = new DeadlockException('After the commit.', 0, self::failure(self::SERIALIZATION_FAILURE, '40001'));

        $thrown = $this->failed(function (Connection $connection) use ($failure): mixed {

            $connection->afterCommit(static fn (): never => throw $failure);

            return $connection->table(self::TABLE)->insert(['run' => $this->runs]);
        });

        self::assertSame($failure, $thrown);
        self::assertSame(1, $this->runs);
        self::assertSame([1], $this->storedRuns());
    }

    /**
     * What running the work in a retried transaction of three attempts threw,
     * each run counted; `null` when it answered.
     *
     * @param  \Closure(\Illuminate\Database\Connection): mixed  $work
     * @return ?\Throwable
     */
    private function failed(\Closure $work): ?\Throwable
    {
        try {
            RetriedTransaction::run($this->database(), function (Connection $connection) use ($work): mixed {
                $this->runs++;

                return $work($connection);
            }, 3);
        } catch (\Throwable $exception) {
            return $exception;
        }

        return null;
    }

    /**
     * Each run the table holds.
     *
     * @return list<int>
     */
    private function storedRuns(): array
    {
        $runs = $this->database()->table(self::TABLE)->pluck('run')->all();

        return array_values(array_map(static fn (mixed $run): int => is_numeric($run) ? (int) $run : -1, $runs));
    }

    /**
     * The storage connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function database(): Connection
    {
        return DB::connection(StorageConnection::name());
    }

    /**
     * A failed statement, as Laravel throws it, with the driver's message and
     * code.
     *
     * @param  string  $message
     * @param  int|string  $code
     * @return \Illuminate\Database\QueryException
     */
    private static function failure(string $message, int|string $code): QueryException
    {
        $driver = new \PDOException($message);

        (new \ReflectionProperty(\Exception::class, 'code'))->setValue($driver, $code);

        return new QueryException('testing', 'update "retried_rows" set "run" = 0', [], $driver);
    }
}
