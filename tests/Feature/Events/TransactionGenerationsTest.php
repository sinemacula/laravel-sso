<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Events\TransactionGenerations;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\TestCase;

/**
 * Feature tests for the count of outermost transactions the after-commit
 * dispatch compares generations by, against real transactions on whichever
 * engine the suite runs on and a second connection: each outermost begin counts
 * once, a savepoint never does, each connection is counted apart, and one count
 * serves the whole process.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TransactionGenerations::class)]
#[CoversClass(SsoServiceProvider::class)]
final class TransactionGenerationsTest extends TestCase
{
    /** @var string The second connection, kept apart from the default. */
    private const string SEPARATE = 'sso_separate_generations';

    /**
     * A connection no transaction has begun on is in generation `0`.
     *
     * @return void
     */
    public function testAConnectionStartsAtNought(): void
    {
        self::assertSame(0, $this->generations()->current(self::SEPARATE));
        self::assertSame(0, $this->generations()->current('sso_never_used'));
    }

    /**
     * Each outermost transaction begun advances its connection's generation by
     * one, whether it then commits or rolls back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachOutermostBeginAdvancesTheGenerationByOne(): void
    {
        $separate = DB::connection(self::SEPARATE);

        $separate->beginTransaction();

        self::assertSame(1, $this->generations()->current(self::SEPARATE));

        $separate->commit();

        self::assertSame(1, $this->generations()->current(self::SEPARATE));

        $separate->beginTransaction();
        $separate->rollBack();

        self::assertSame(2, $this->generations()->current(self::SEPARATE));

        $separate->transaction(static function (): void {});

        self::assertSame(3, $this->generations()->current(self::SEPARATE));
    }

    /**
     * A savepoint, however deep, and its commit or rollback, leave the
     * generation of the transaction it sits in as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASavepointDoesNotAdvanceTheGeneration(): void
    {
        $name   = $this->defaultConnection();
        $before = $this->generations()->current($name);

        DB::beginTransaction();

        self::assertSame($before + 1, $this->generations()->current($name));

        DB::beginTransaction();
        DB::beginTransaction();

        self::assertSame(3, DB::transactionLevel());
        self::assertSame($before + 1, $this->generations()->current($name));

        DB::rollBack();
        DB::commit();
        DB::transaction(static function (): void {});

        self::assertSame($before + 1, $this->generations()->current($name));

        DB::commit();

        self::assertSame($before + 1, $this->generations()->current($name));
    }

    /**
     * Each connection is counted apart: a transaction on one, even opened
     * inside another's, advances only its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGenerationIsPerConnection(): void
    {
        $name     = $this->defaultConnection();
        $before   = $this->generations()->current($name);
        $separate = DB::connection(self::SEPARATE);

        $separate->beginTransaction();

        self::assertSame(1, $this->generations()->current(self::SEPARATE));
        self::assertSame($before, $this->generations()->current($name));

        DB::beginTransaction();

        self::assertSame(1, $this->generations()->current(self::SEPARATE));
        self::assertSame($before + 1, $this->generations()->current($name));

        DB::commit();
        $separate->commit();

        DB::transaction(static function (): void {});

        self::assertSame(1, $this->generations()->current(self::SEPARATE));
        self::assertSame($before + 2, $this->generations()->current($name));
    }

    /**
     * The count is one for the process: the same instance is resolved every
     * time, and it survives the scoped instances being forgotten between
     * requests and jobs, with its count.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOneCountServesTheProcess(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app         = $this->app;
        $generations = $this->generations();

        DB::connection(self::SEPARATE)->transaction(static function (): void {});

        $app->forgetScopedInstances();

        self::assertSame($generations, $this->generations());
        self::assertSame(1, $this->generations()->current(self::SEPARATE));
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
     * The count, as the container gives it.
     *
     * @return \SineMacula\Laravel\Sso\Events\TransactionGenerations
     */
    private function generations(): TransactionGenerations
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(TransactionGenerations::class);
    }

    /**
     * The name of the default connection.
     *
     * @return string
     */
    private function defaultConnection(): string
    {
        return (string) DB::connection()->getName();
    }
}
