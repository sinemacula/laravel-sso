<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Config;
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
 * A test of what the counters cost asks for them on a connection of their own
 * (`useSeparateCounters()`): the same database engine under another connection
 * name, recorded apart, so a budget says which statement went to which.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class PerformanceContractTestCase extends TestCase
{
    /** @var string The connection `useSeparateCounters()` moves the counters to. */
    protected const string COUNTERS = 'sso_counters';

    /** @var list<string> File names of the shipped migrations. */
    private const array MIGRATIONS = [
        '2026_10_31_000000_create_sso_single_use_keys_table.php',
        '2026_10_31_000001_create_sso_rate_limits_table.php',
        '2026_11_01_000000_create_sso_connections_table.php',
        '2026_11_01_000001_create_sso_keys_table.php',
        '2026_11_02_000000_create_sso_domains_table.php',
        '2026_11_02_000001_create_sso_enforcement_table.php',
        '2026_11_03_000000_create_sso_links_table.php',
        '2026_11_03_000001_create_sso_authorization_requests_table.php',
        '2026_11_03_000002_create_sso_handoff_codes_table.php',
        '2026_11_03_000003_create_sso_identity_guards_table.php',
    ];

    /** @var list<string> The tables the shipped migrations create, by their default names. */
    private const array TABLES = [
        'sso_single_use_keys', 'sso_rate_limits', 'sso_connections', 'sso_keys', 'sso_domains', 'sso_enforcement', 'sso_links',
        'sso_authorization_requests', 'sso_handoff_codes', 'sso_identity_guards',
    ];

    /** @var string What a statement may start with: data manipulation, or a transaction's savepoint. */
    private const string RUNTIME_STATEMENT = '/^\s*(?:select|insert|update|delete|savepoint|release|rollback)\b/i';

    /** @var string What a write starts with. */
    private const string WRITE = '/^\s*(?:insert|update|delete)\b/i';

    /** @var string What a transaction's own statement starts with; it is neither a read nor a write. */
    private const string TRANSACTION = '/^\s*(?:savepoint|release|rollback)\b/i';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    protected FixedClock $clock;

    /** @var \ArrayObject<int, string> Every statement sent on the storage connection while recording. */
    private \ArrayObject $statements;

    /** @var \ArrayObject<int, string> Every statement sent on the counters' own connection while recording. */
    private \ArrayObject $counterStatements;

    /** @var bool Whether the counters are on a connection of their own. */
    private bool $separateCounters = false;

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

        $this->clock             = new FixedClock('2026-10-31T12:00:15Z');
        $this->statements        = new \ArrayObject;
        $this->counterStatements = new \ArrayObject;

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
     * Drop the shipped tables, the counters' from their own connection when
     * they moved there, so a persistent database starts the next test without
     * them.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->separateCounters) {
            Schema::connection(self::COUNTERS)->dropIfExists('sso_rate_limits');
        }

        foreach (self::TABLES as $table) {
            Schema::dropIfExists($table);
        }

        parent::tearDown();
    }

    /**
     * Move the counters to a connection of their own, on the same engine as the
     * storage connection and recorded apart. SQLite's is another database in
     * memory; a server's is the same database, so the table moves rather than
     * being copied. Call it from `setUp()`, before a counter is written.
     *
     * @return void
     */
    protected function useSeparateCounters(): void
    {
        Schema::dropIfExists('sso_rate_limits');

        Config::set('database.connections.' . self::COUNTERS, Config::array('database.connections.' . Config::string('database.default')));
        Config::set('sso.rate_limits.connection', self::COUNTERS);

        self::migration(self::MIGRATIONS[1])->up(); // @phpstan-ignore method.notFound

        $this->separateCounters = true;

        DB::connection(self::COUNTERS)->beforeExecuting(function (string $query): void {
            if (!$this->recording) {
                return;
            }

            $this->counterStatements->append($query);
        });
    }

    /**
     * Run the callback and assert it sent exactly the reads and writes given,
     * and nothing but data manipulation; answer what it returned. Reads and
     * writes are the storage connection's; those of the counters' own
     * connection, when `useSeparateCounters()` moved them, are the last two.
     *
     * @template TResult
     *
     * @param  int  $reads
     * @param  int  $writes
     * @param  callable(): TResult  $callback
     * @param  int  $counterReads
     * @param  int  $counterWrites
     * @return TResult
     */
    protected function assertQueryBudget(int $reads, int $writes, callable $callback, int $counterReads = 0, int $counterWrites = 0): mixed
    {
        $this->statements->exchangeArray([]);
        $this->counterStatements->exchangeArray([]);
        $this->recording = true;

        try {
            $result = $callback();
        } finally {
            $this->recording = false;
        }

        $this->assertStatements('read', 'write', $this->statementsSent(), $reads, $writes);
        $this->assertStatements('counters\' read', 'counters\' write', $this->counterStatementsSent(), $counterReads, $counterWrites);

        return $result;
    }

    /**
     * What the last budget sent on the storage connection, in order.
     *
     * @return list<string>
     */
    protected function statementsSent(): array
    {
        return array_values($this->statements->getArrayCopy());
    }

    /**
     * What the last budget sent on the counters' own connection, in order.
     *
     * @return list<string>
     */
    protected function counterStatementsSent(): array
    {
        return array_values($this->counterStatements->getArrayCopy());
    }

    /**
     * Assert the statements of one connection are exactly the reads and writes
     * given, and nothing but data manipulation.
     *
     * @param  string  $readName
     * @param  string  $writeName
     * @param  list<string>  $sent
     * @param  int  $reads
     * @param  int  $writes
     * @return void
     */
    private function assertStatements(string $readName, string $writeName, array $sent, int $reads, int $writes): void
    {
        $statements = array_values(array_filter($sent, static fn (string $sql): bool => preg_match(self::TRANSACTION, $sql) !== 1));
        $written    = array_filter($statements, static fn (string $sql): bool => preg_match(self::WRITE, $sql) === 1);
        $listed     = implode(' | ', $sent);

        foreach ($sent as $sql) {
            static::assertMatchesRegularExpression(self::RUNTIME_STATEMENT, $sql, 'A runtime statement must be data manipulation only.');
        }

        static::assertSame($reads, count($statements) - count($written), "Unexpected {$readName} budget. Statements: {$listed}");
        static::assertCount($writes, $written, "Unexpected {$writeName} budget. Statements: {$listed}");
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
