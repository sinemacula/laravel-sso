<?php

declare(strict_types = 1);

namespace Tests\Feature\SingleUse;

use Illuminate\Database\DeadlockException;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;
use Tests\Concerns\RunsInTimezone;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the default single-use store on the shipped table: a key is
 * recorded once in its namespace until its expiry, then may be recorded
 * again; only its digest is stored; a database error is thrown, never answered;
 * and the rows live on the storage connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseSingleUseStore::class)]
final class DatabaseSingleUseStoreTest extends TestCase
{
    use RunsInTimezone;

    /** @var string Absolute path to the shipped single-use keys migration. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The table's default name. */
    private const string TABLE = 'sso_single_use_keys';

    /** @var string The second connection the storage is moved to. */
    private const string STORE = 'package_store';

    /** @var string A key that may be a secret. */
    private const string KEY = 'handoff-code-that-must-stay-secret';

    /** @var string What MySQL says when it rolls a statement back as a deadlock. */
    private const string DEADLOCK = 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock; try restarting transaction';

    /** @var \Tests\Fixtures\FixedClock The clock the store reads. */
    private FixedClock $clock;

    /**
     * Bind the fixed clock and create the shipped table on the storage
     * connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock;

        $this->app?->instance(Clock::class, $this->clock);

        $this->migration()->up(); // @phpstan-ignore method.notFound
    }

    /**
     * Drop the table from the default connection, wherever a test moved the
     * storage, so a persistent database starts the next test without it.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        config()->set('sso.storage.connection', null);

        Schema::dropIfExists(self::TABLE);

        parent::tearDown();
    }

    /**
     * The first record of a key is `recorded`; every later one, whatever its
     * expiry, is `seen`, and the table holds the key once.
     *
     * @return void
     */
    public function testRecordsAKeyOnceAndThenSeesIt(): void
    {
        $store = $this->store();

        self::assertSame(SingleUseOutcome::RECORDED, $store->record('handoff_code', self::KEY, $this->clock->now()->addMinute()));
        self::assertSame(SingleUseOutcome::SEEN, $store->record('handoff_code', self::KEY, $this->clock->now()->addMinute()));
        self::assertSame(SingleUseOutcome::SEEN, $store->record('handoff_code', self::KEY, $this->clock->now()->addHour()));
        self::assertSame(1, DB::table(self::TABLE)->count());
    }

    /**
     * The container's single-use store is this one, on the bound clock: an
     * expiry a second after the fixed clock's now is accepted, though it is
     * long past by the system clock.
     *
     * @return void
     */
    public function testTheContainerResolvesTheDatabaseStoreOnTheBoundClock(): void
    {
        $store = $this->app?->make(SingleUseStore::class);

        self::assertInstanceOf(DatabaseSingleUseStore::class, $store);
        self::assertSame(SingleUseOutcome::RECORDED, $store->record('handoff_code', self::KEY, $this->clock->now()->addSecond()));
    }

    /**
     * The same key is recorded once in each namespace: the namespace is part of
     * what is held.
     *
     * @return void
     */
    public function testRecordsTheSameKeyInEachNamespace(): void
    {
        $store = $this->store();
        $until = $this->clock->now()->addMinute();

        self::assertSame(SingleUseOutcome::RECORDED, $store->record('saml_assertion', self::KEY, $until));
        self::assertSame(SingleUseOutcome::RECORDED, $store->record('authorization_request', self::KEY, $until));
        self::assertSame(SingleUseOutcome::SEEN, $store->record('saml_assertion', self::KEY, $until));
        self::assertSame(SingleUseOutcome::SEEN, $store->record('authorization_request', self::KEY, $until));
        self::assertSame(2, DB::table(self::TABLE)->count());
    }

    /**
     * A key is held until its expiry and released from the second it names:
     * recorded again then, its old row replaced by the new one.
     *
     * @return void
     */
    public function testRecordsAKeyAgainOnceItsExpiryHasPassed(): void
    {
        $store = $this->store();

        self::assertSame(SingleUseOutcome::RECORDED, $store->record('saml_assertion', self::KEY, $this->clock->now()->addMinute()));

        $first = DB::table(self::TABLE)->value('id');

        $this->clock->advance(59);

        self::assertSame(SingleUseOutcome::SEEN, $store->record('saml_assertion', self::KEY, $this->clock->now()->addMinute()));

        $this->clock->advance(1);

        self::assertSame(SingleUseOutcome::RECORDED, $store->record('saml_assertion', self::KEY, $this->clock->now()->addMinutes(2)));

        self::assertSame(1, DB::table(self::TABLE)->count());

        $row = DB::table(self::TABLE)->sole();

        self::assertNotEquals($first, $row->id);
        self::assertSame('2026-10-31 12:03:00', $row->expires_at);
        self::assertSame(SingleUseOutcome::SEEN, $store->record('saml_assertion', self::KEY, $this->clock->now()->addMinute()));
    }

    /**
     * An expiry with a fraction of a second is kept to the whole second after
     * it, so the key is never released before its expiry.
     *
     * @return void
     */
    public function testRoundsASubSecondExpiryUp(): void
    {
        $store = $this->store();

        self::assertSame(SingleUseOutcome::RECORDED, $store->record('handoff_code', self::KEY, $this->clock->now()->addMilliseconds(500)));
        self::assertSame('2026-10-31 12:00:01', DB::table(self::TABLE)->value('expires_at'));
        self::assertSame(SingleUseOutcome::SEEN, $store->record('handoff_code', self::KEY, $this->clock->now()->addMinute()));

        $this->clock->advance(1);

        self::assertSame(SingleUseOutcome::RECORDED, $store->record('handoff_code', self::KEY, $this->clock->now()->addMinute()));
    }

    /**
     * The expiry is stored in UTC, whatever timezone it is given in and
     * whatever the application timezone, so it compares with the clock as the
     * instant it is.
     *
     * @return void
     */
    public function testStoresTheExpiryInUtc(): void
    {
        $until = $this->clock->now()->addMinute()->setTimezone('Asia/Tokyo');

        $this->inTimezone('America/New_York', function () use ($until): void {
            self::assertSame(SingleUseOutcome::RECORDED, $this->store()->record('handoff_code', self::KEY, $until));
        });

        self::assertSame('2026-10-31 12:01:00', DB::table(self::TABLE)->value('expires_at'));
    }

    /**
     * In the hour a daylight-saving fall-back repeats, a key held past the
     * clock's now is still held: at 00:40 UTC (01:40 BST) a key held until
     * 01:30 UTC (01:30 GMT) is `seen`, and pruning keeps it, though in London's
     * wall-clock time its expiry reads as earlier than now.
     *
     * @return void
     */
    public function testHoldsAKeyThroughADaylightSavingFallBack(): void
    {
        $this->inTimezone('Europe/London', function (): void {
            $clock = new FixedClock('2026-10-25T00:40:00Z');
            $until = $clock->now()->setTime(1, 30);

            $this->app?->instance(Clock::class, $clock);

            $store = new DatabaseSingleUseStore($clock);

            self::assertSame(SingleUseOutcome::RECORDED, $store->record('saml_assertion', self::KEY, $until));
            self::assertSame(SingleUseOutcome::SEEN, $store->record('saml_assertion', self::KEY, $until));
            self::assertSame(0, (new SingleUseKey)->prunable()->count());

            $clock->advance(50 * 60);

            self::assertSame(1, (new SingleUseKey)->prunable()->count());
            self::assertSame(SingleUseOutcome::RECORDED, $store->record('saml_assertion', self::KEY, $until->addHour()));
        });
    }

    /**
     * A record never deletes a row still held, its own or another key's, and
     * leaves another key's expired row to pruning.
     *
     * @return void
     */
    public function testNeverDeletesARowStillHeld(): void
    {
        $store = $this->store();

        DB::table(self::TABLE)->insert([
            'namespace'  => 'handoff_code',
            'key_digest' => hash('sha256', 'expired-key'),
            'expires_at' => '2026-10-31 11:59:59',
        ]);

        self::assertSame(SingleUseOutcome::RECORDED, $store->record('handoff_code', self::KEY, $this->clock->now()->addMinute()));

        $held = DB::table(self::TABLE)->where('key_digest', hash('sha256', self::KEY))->first();

        self::assertNotNull($held);

        $this->clock->advance(30);

        self::assertSame(SingleUseOutcome::SEEN, $store->record('handoff_code', self::KEY, $this->clock->now()->addMinute()));
        self::assertSame(SingleUseOutcome::RECORDED, $store->record('handoff_code', 'another-key', $this->clock->now()->addMinute()));

        $after = DB::table(self::TABLE)->where('key_digest', hash('sha256', self::KEY))->first();

        self::assertEquals($held, $after);
        self::assertSame(3, DB::table(self::TABLE)->count());
        self::assertSame(1, DB::table(self::TABLE)->where('key_digest', hash('sha256', 'expired-key'))->count());
    }

    /**
     * Only the key's lower-case hex SHA-256 digest is stored: the key itself
     * appears nowhere in the table.
     *
     * @return void
     */
    public function testStoresOnlyTheDigestOfTheKey(): void
    {
        $this->store()->record('handoff_code', self::KEY, $this->clock->now()->addMinute());

        self::assertSame(1, DB::table(self::TABLE)->count());

        $row = DB::table(self::TABLE)->sole();

        self::assertSame('handoff_code', $row->namespace);
        self::assertSame(hash('sha256', self::KEY), $row->key_digest);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $row->key_digest);
        self::assertStringNotContainsString(self::KEY, (string) json_encode(DB::table(self::TABLE)->get()));
    }

    /**
     * Every character a namespace may hold is accepted, from 1 to 64 of them.
     *
     * @return void
     */
    public function testAcceptsEveryAllowedNamespace(): void
    {
        $store = $this->store();
        $until = $this->clock->now()->addMinute();

        $longest = str_pad('abcdefghijklmnopqrstuvwxyz0123456789_.:-', 64, 'z');

        self::assertSame(SingleUseOutcome::RECORDED, $store->record($longest, self::KEY, $until));
        self::assertSame(SingleUseOutcome::RECORDED, $store->record('a', self::KEY, $until));
        self::assertSame([$longest, 'a'], DB::table(self::TABLE)->orderBy('id')->pluck('namespace')->all());
    }

    /**
     * A key recorded by another server between the release of its expired row
     * and the second insert is `seen`: the second insert is refused by the
     * index like the first, and the other server's row is kept.
     *
     * @return void
     */
    public function testAKeyRecordedBetweenTheReleaseAndTheRetryIsSeen(): void
    {
        $digest = hash('sha256', self::KEY);

        DB::table(self::TABLE)->insert(['namespace' => 'handoff_code', 'key_digest' => $digest, 'expires_at' => '2026-10-31 11:59:00']);

        $raced = false;

        DB::listen(static function (QueryExecuted $query) use (&$raced, $digest): void {
            if ($raced || !str_starts_with(strtolower(ltrim($query->sql)), 'delete')) {
                return;
            }

            $raced = true;

            $query->connection->table(self::TABLE)->insert(['namespace' => 'handoff_code', 'key_digest' => $digest, 'expires_at' => '2026-10-31 12:05:00']);
        });

        self::assertSame(SingleUseOutcome::SEEN, $this->store()->record('handoff_code', self::KEY, $this->clock->now()->addMinute()));
        self::assertTrue($raced);
        self::assertSame(['2026-10-31 12:05:00'], DB::table(self::TABLE)->pluck('expires_at')->all());
    }

    /**
     * An insert the database rolls back as a deadlock wrote nothing, so the
     * store tries it again in the transaction it opened, and records the key
     * once.
     *
     * @return void
     */
    public function testTriesAnInsertAgainAfterADeadlock(): void
    {
        $deadlocks = $this->deadlockInserts(2);

        self::assertSame(SingleUseOutcome::RECORDED, $this->store()->record('handoff_code', self::KEY, $this->clock->now()->addMinute()));
        self::assertSame(2, $deadlocks->count);
        self::assertSame(1, DB::table(self::TABLE)->count());
    }

    /**
     * A deadlock on every attempt is thrown after the third, never answered.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThrowsADeadlockThatPersists(): void
    {
        $deadlocks = $this->deadlockInserts(PHP_INT_MAX);

        try {
            $this->store()->record('handoff_code', self::KEY, $this->clock->now()->addMinute());

            self::fail('Expected the deadlock to be thrown.');
        } catch (QueryException $exception) {
            self::assertStringContainsString('Deadlock found', $exception->getMessage());
        }

        self::assertSame(3, $deadlocks->count);
        self::assertSame(0, DB::table(self::TABLE)->count());
    }

    /**
     * Inside the caller's transaction a deadlock is thrown at once: the
     * database has rolled the caller's transaction back too, so there is
     * nothing to try again in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThrowsADeadlockInsideTheCallersTransaction(): void
    {
        $deadlocks = $this->deadlockInserts(1);

        try {
            DB::transaction(fn (): SingleUseOutcome => $this->store()->record('handoff_code', self::KEY, $this->clock->now()->addMinute()));

            self::fail('Expected the deadlock to be thrown.');
        } catch (DeadlockException $exception) {
            self::assertStringContainsString('Deadlock found', $exception->getMessage());
        }

        self::assertSame(1, $deadlocks->count);
        self::assertSame(0, DB::transactionLevel());
        self::assertSame(0, DB::table(self::TABLE)->count());
    }

    /**
     * A table that is not there is a database error, thrown as it is, never
     * answered `seen` (nor `recorded`).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThrowsADatabaseErrorRatherThanAnswering(): void
    {
        Schema::drop(self::TABLE);

        try {
            $this->store()->record('handoff_code', self::KEY, $this->clock->now()->addMinute());

            self::fail('Expected the database error to be thrown.');
        } catch (QueryException $exception) {
            self::assertNotInstanceOf(UniqueConstraintViolationException::class, $exception);
            self::assertStringNotContainsString(self::KEY, $exception->getMessage());
        }
    }

    /**
     * With the storage on a second connection, the keys are recorded and seen
     * there, and the default connection's table is never written.
     *
     * @return void
     */
    public function testRecordsOnTheStorageConnection(): void
    {
        config()->set('sso.storage.connection', self::STORE);

        $this->migration()->up(); // @phpstan-ignore method.notFound

        $store = $this->store();

        self::assertSame(SingleUseOutcome::RECORDED, $store->record('handoff_code', self::KEY, $this->clock->now()->addMinute()));
        self::assertSame(SingleUseOutcome::SEEN, $store->record('handoff_code', self::KEY, $this->clock->now()->addMinute()));
        self::assertSame(1, DB::connection(self::STORE)->table(self::TABLE)->count());
        self::assertSame(0, DB::connection('testing')->table(self::TABLE)->count());
    }

    /**
     * The store holds nothing but its clock, so nothing of one call reaches the
     * next.
     *
     * @return void
     */
    public function testHoldsNothingButItsClock(): void
    {
        $class = new \ReflectionClass(DatabaseSingleUseStore::class);

        self::assertTrue($class->isReadOnly());
        self::assertSame(['clock'], array_map(static fn (\ReflectionProperty $property): string => $property->getName(), $class->getProperties()));
        self::assertSame([], $class->getStaticProperties());
    }

    /**
     * Add the second connection the storage is moved to.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('database.connections.' . self::STORE, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
    }

    /**
     * Have the database report the next inserts as deadlocks, as MySQL does
     * when it rolls an insert back: each runs, then fails, so the transaction
     * around it undoes it. Returns the count of deadlocks reported so far.
     *
     * @param  int  $times
     * @return \stdClass
     */
    private function deadlockInserts(int $times): \stdClass
    {
        $deadlocks = (object) ['count' => 0];

        DB::listen(static function (QueryExecuted $query) use ($deadlocks, $times): void {
            if ($deadlocks->count >= $times || !str_starts_with(strtolower(ltrim($query->sql)), 'insert')) {
                return;
            }

            $deadlocks->count++;

            throw new QueryException($query->connectionName, $query->sql, $query->bindings, new \PDOException(self::DEADLOCK));
        });

        return $deadlocks;
    }

    /**
     * A store on the fixed clock.
     *
     * @return \SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore
     */
    private function store(): DatabaseSingleUseStore
    {
        return new DatabaseSingleUseStore($this->clock);
    }

    /**
     * Require the shipped anonymous-class migration and return it.
     *
     * @return \Illuminate\Database\Migrations\Migration
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function migration(): Migration
    {
        $migration = include self::MIGRATION_PATH;

        if (!$migration instanceof Migration) {
            self::fail('The single-use keys migration did not return a Migration instance.');
        }

        return $migration;
    }
}
