<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Contracts\Clock;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Shared base for the deterministic query-budget tests of the package's
 * database-backed defaults.
 *
 * It binds a fixed clock, creates the shipped tables, and records every
 * statement sent on the storage connection, a failing one included, so a test
 * asserts the exact reads and writes a call costs rather than a wall-clock
 * time. Every statement recorded must also be data manipulation only: the
 * package needs nothing but SELECT, INSERT, UPDATE and DELETE at runtime
 * (SSO-11.7), so one that changes the schema fails the budget.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class PerformanceContractTestCase extends TestCase
{
    /** @var list<string> File names of the shipped migrations. */
    private const array MIGRATIONS = [
        '2026_10_31_000000_create_sso_single_use_keys_table.php',
        '2026_10_31_000001_create_sso_rate_limits_table.php',
    ];

    /** @var list<string> The tables the shipped migrations create, by their default names. */
    private const array TABLES = ['sso_single_use_keys', 'sso_rate_limits'];

    /** @var string What a statement may start with: data manipulation, or a transaction's savepoint. */
    private const string RUNTIME_STATEMENT = '/^\s*(?:select|insert|update|delete|savepoint|release|rollback)\b/i';

    /** @var string What a write starts with. */
    private const string WRITE = '/^\s*(?:insert|update|delete)\b/i';

    /** @var string What a transaction's own statement starts with; it is neither a read nor a write. */
    private const string TRANSACTION = '/^\s*(?:savepoint|release|rollback)\b/i';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    protected FixedClock $clock;

    /** @var \ArrayObject<int, string> Every statement sent while recording. */
    private \ArrayObject $statements;

    /** @var bool Whether statements are being recorded. */
    private bool $recording = false;

    /**
     * Bind the fixed clock, create the shipped tables, and listen for every
     * statement before it is sent.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock      = new FixedClock('2026-10-31T12:00:15Z');
        $this->statements = new \ArrayObject;

        $this->app?->instance(Clock::class, $this->clock);

        foreach (self::MIGRATIONS as $migration) {
            self::migration($migration)->up(); // @phpstan-ignore method.notFound
        }

        DB::connection()->beforeExecuting(function (string $query): void {
            if (!$this->recording) {
                return;
            }

            $this->statements->append($query);
        });
    }

    /**
     * Drop the shipped tables, so a persistent database starts the next test
     * without them.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (self::TABLES as $table) {
            Schema::dropIfExists($table);
        }

        parent::tearDown();
    }

    /**
     * Run the callback and assert it sent exactly the reads and writes given,
     * and nothing but data manipulation; answer what it returned.
     *
     * @template TResult
     *
     * @param  int  $reads
     * @param  int  $writes
     * @param  callable(): TResult  $callback
     * @return TResult
     */
    protected function assertQueryBudget(int $reads, int $writes, callable $callback): mixed
    {
        $this->statements->exchangeArray([]);
        $this->recording = true;

        try {
            $result = $callback();
        } finally {
            $this->recording = false;
        }

        $sent       = array_values($this->statements->getArrayCopy());
        $statements = array_values(array_filter($sent, static fn (string $sql): bool => preg_match(self::TRANSACTION, $sql) !== 1));
        $written    = array_filter($statements, static fn (string $sql): bool => preg_match(self::WRITE, $sql) === 1);
        $listed     = implode(' | ', $sent);

        foreach ($sent as $sql) {
            static::assertMatchesRegularExpression(self::RUNTIME_STATEMENT, $sql, 'A runtime statement must be data manipulation only.');
        }

        static::assertSame($reads, count($statements) - count($written), "Unexpected read budget. Statements: {$listed}");
        static::assertCount($writes, $written, "Unexpected write budget. Statements: {$listed}");

        return $result;
    }

    /**
     * Require a shipped anonymous-class migration and return it.
     *
     * @param  string  $file
     * @return \Illuminate\Database\Migrations\Migration
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private static function migration(string $file): Migration
    {
        $migration = include dirname(__DIR__, 2) . '/database/migrations/' . $file;

        if (!$migration instanceof Migration) {
            static::fail("The migration [{$file}] did not return a Migration instance.");
        }

        return $migration;
    }
}
