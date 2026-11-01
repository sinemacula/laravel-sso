<?php

declare(strict_types = 1);

namespace Tests\Integration\Flows;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\ConsumptionResult;
use SineMacula\Laravel\Sso\Flows\Enums\ConsumptionStatus;
use SineMacula\Laravel\Sso\Flows\RequestConsumption;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Races the consumption of one authorisation request across processes, each
 * with its own database connection, on PostgreSQL and MySQL (SSO-5.1,
 * SSO-11.5): however they interleave, exactly one consumes the request, every
 * other finds it `replayed`, none fails, and the request is marked and recorded
 * in the single-use store once. Each race runs with every process consuming
 * plainly, and again with each inside a transaction of its own that read the
 * request before the race began, so the locking read must see what another
 * process committed rather than its transaction's snapshot (MySQL's `REPEATABLE
 * READ`). Races by the state and by the SAML request id both run.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequestConsumption::class)]
final class ConcurrentRequestConsumptionTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var int Processes racing in each test. */
    private const int PROCESSES = 8;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The protocol state the request was started with. */
    private const string STATE = 'the-protocol-state-of-the-raced-request-01';

    /** @var string The SAML request id the request was started with. */
    private const string SAML_REQUEST_ID = '_raced-request';

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the request was started through. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Models\AuthorizationRequest The request every process races to consume. */
    private AuthorizationRequest $request;

    /** @var string Directory the processes report their outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, bind a fixed clock,
     * register the application, create the tables, the connection and the
     * request, and make the directory the processes report in.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        config()->set('sso.applications', [
            'web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
        ]);

        $this->createConnectionTables();
        $this->createFlowTables();
        self::singleUseMigration()->up(); // @phpstan-ignore method.notFound

        $this->connection = $this->makeConnection(['enabled' => true]);
        $this->request    = $this->makeAuthorizationRequest($this->connection, [
            'state_digest'    => hash('sha256', self::STATE),
            'saml_request_id' => self::SAML_REQUEST_ID,
            'code_verifier'   => app(SecretEncrypter::class)->encrypt('the-pkce-verifier-of-the-raced-request-0123'),
        ]);

        $this->outcomes = sys_get_temp_dir() . '/request-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove this test's outcomes and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if (isset($this->outcomes) && is_dir($this->outcomes)) {

            foreach (glob($this->outcomes . '/*') ?: [] as $file) {
                @unlink($file);
            }

            @rmdir($this->outcomes);
        }

        if (isset($this->request)) {
            self::singleUseMigration()->down(); // @phpstan-ignore method.notFound
            $this->dropFlowTables();
            $this->dropConnectionTables();
        }

        parent::tearDown();
    }

    /**
     * Processes racing to consume the request by its state: exactly one
     * consumes it.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacersByStateConsumesTheRequest(): void
    {
        $this->assertConsumedOnce($this->race(Correlation::solicited(self::STATE, self::SAML_REQUEST_ID)));
    }

    /**
     * The same race, each inside a transaction of its own that read the request
     * before the race began.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacersByStateInsideACallersTransactionConsumesTheRequest(): void
    {
        $this->assertConsumedOnce($this->race(Correlation::solicited(self::STATE, self::SAML_REQUEST_ID), true));
    }

    /**
     * Processes racing to consume the request by its SAML request id: exactly
     * one consumes it.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacersBySamlRequestIdConsumesTheRequest(): void
    {
        $this->assertConsumedOnce($this->race(Correlation::solicited(null, self::SAML_REQUEST_ID)));
    }

    /**
     * The same race, each inside a transaction of its own that read the request
     * before the race began.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacersBySamlRequestIdInsideACallersTransactionConsumesTheRequest(): void
    {
        $this->assertConsumedOnce($this->race(Correlation::solicited(null, self::SAML_REQUEST_ID), true));
    }

    /**
     * Assert exactly one process consumed the request, every other found it
     * replayed, the request is marked consumed, and the store holds it once.
     *
     * @param  list<string>  $outcomes
     * @return void
     */
    private function assertConsumedOnce(array $outcomes): void
    {
        $listed = implode(', ', $outcomes);

        self::assertCount(1, array_keys($outcomes, ConsumptionStatus::CONSUMED->value, true), $listed);
        self::assertCount(self::PROCESSES - 1, array_keys($outcomes, ConsumptionStatus::REPLAYED->value, true), $listed);
        self::assertNotNull(AuthorizationRequest::query()->whereKey($this->request->id)->sole()->consumed_at);
        self::assertSame(1, DB::table(StorageConnection::table('single_use.table'))->where('namespace', RequestConsumption::NAMESPACE)->count());
    }

    /**
     * Fork the processes, have each consume at the same moment on a connection
     * of its own, and collect what each reported.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @param  bool  $inTransaction
     * @return list<string>
     */
    private function race(Correlation $correlation, bool $inTransaction = false): array
    {
        DB::disconnect();

        $start = microtime(true) + 0.5;
        $pids  = [];

        for ($process = 0; $process < self::PROCESSES; $process++) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $start, $correlation, $inTransaction);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        $outcomes = [];

        for ($process = 0; $process < self::PROCESSES; $process++) {
            $outcomes[] = (string) file_get_contents("{$this->outcomes}/{$process}");
        }

        return $outcomes;
    }

    /**
     * In a forked process: open a connection of its own and build the
     * consumption, so only the consumption runs after the start, wait for the
     * start, consume, report the outcome, and end without running the parent's
     * shutdown.
     *
     * Racing inside a transaction, the process opens one and reads the request
     * before the start, so the transaction's snapshot predates every
     * consumption, and commits after its own.
     *
     * @param  int  $process
     * @param  float  $start
     * @param  \SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @param  bool  $inTransaction
     * @return never
     */
    private function runInChild(int $process, float $start, Correlation $correlation, bool $inTransaction): never
    {
        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            /** @var \Illuminate\Foundation\Application $app */
            $app         = $this->app;
            $consumption = $app->make(RequestConsumption::class);
            $database    = DB::connection(StorageConnection::name());

            if ($inTransaction) {
                $database->beginTransaction();
                AuthorizationRequest::query()->whereKey($this->request->id)->get();
            }

            $wait = $start - microtime(true);

            if ($wait > 0) {
                usleep((int) ($wait * 1000000));
            }

            $result = $consumption->consume($this->connection, $correlation);

            if ($inTransaction) {
                $database->commit();
            }

            $outcome = self::outcome($result);
        } catch (\Throwable $e) {
            $outcome = 'error: ' . $e->getMessage();
        }

        file_put_contents("{$this->outcomes}/{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * The status the result reports, with its reason when it was not consumed
     * or replayed.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\ConsumptionResult  $result
     * @return string
     */
    private static function outcome(ConsumptionResult $result): string
    {
        return $result->isConsumed() || $result->isReplayed() ? $result->status->value : $result->status->value . ':' . $result->reason?->value;
    }

    /**
     * The shipped migration of the single-use keys.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function singleUseMigration(): Migration
    {
        return require dirname(__DIR__, 3) . self::SINGLE_USE_MIGRATION;
    }
}
