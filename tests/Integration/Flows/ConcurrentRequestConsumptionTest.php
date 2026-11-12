<?php

declare(strict_types = 1);

namespace Tests\Integration\Flows;

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
 * Races consumption of one request across processes, plainly and inside
 * transactions that read first. Skipped on SQLite and without `pcntl`.
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

    /** @var string The protocol state the request was started with. */
    private const string STATE = 'the-protocol-state-of-the-raced-request-01';

    /** @var string The SAML request id the request was started with. */
    private const string SAML_REQUEST_ID = '_raced-request';

    /** @var string What the one racer that consumes a request with no RelayState reports. */
    private const string MISMATCH = 'refused:request_mismatch';

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the request was started through. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Models\AuthorizationRequest The request every process races to consume. */
    private AuthorizationRequest $request;

    /** @var string Directory the processes report their outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, bind the collaborators,
     * and seed the request.
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

        $this->usePackageTables();

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
     * Remove this test's outcomes.
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

        parent::tearDown();
    }

    /**
     * Processes race to consume the request by its state; exactly one does.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacersByStateConsumesTheRequest(): void
    {
        $this->assertConsumedOnce($this->race(Correlation::solicited(self::STATE, self::SAML_REQUEST_ID)));
    }

    /**
     * The same race, each inside a transaction that read the request first.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacersByStateInsideACallersTransactionConsumesTheRequest(): void
    {
        $this->assertConsumedOnce($this->race(Correlation::solicited(self::STATE, self::SAML_REQUEST_ID), true));
    }

    /**
     * Processes race by SAML id without `RelayState`; one consumes and is
     * refused for it.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacersWithoutRelayStateConsumesTheRequest(): void
    {
        $this->assertConsumedOnce($this->race(Correlation::solicited(null, self::SAML_REQUEST_ID)), self::MISMATCH);
    }

    /**
     * The same race, each inside a transaction that read the request first.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacersWithoutRelayStateInsideACallersTransactionConsumesTheRequest(): void
    {
        $this->assertConsumedOnce($this->race(Correlation::solicited(null, self::SAML_REQUEST_ID), true), self::MISMATCH);
    }

    /**
     * Assert one process consumed, the rest found it replayed, and the store
     * holds it once.
     *
     * @param  list<string>  $outcomes
     * @param  string  $first
     * @return void
     */
    private function assertConsumedOnce(array $outcomes, string $first = 'consumed'): void
    {
        $listed = implode(', ', $outcomes);

        self::assertCount(1, array_keys($outcomes, $first, true), $listed);
        self::assertCount(self::PROCESSES - 1, array_keys($outcomes, ConsumptionStatus::REPLAYED->value, true), $listed);
        self::assertNotNull(AuthorizationRequest::query()->whereKey($this->request->id)->sole()->consumed_at);
        self::assertSame(1, DB::table(StorageConnection::table('single_use.table'))->where('namespace', RequestConsumption::NAMESPACE)->count());
    }

    /**
     * Fork the processes, have each consume at the same moment on its own
     * connection, and collect the results.
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
     * In a child: build the consumption, wait for the start, consume and
     * report; in a transaction, read first.
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
     * The result's status, with its reason unless consumed or replayed.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\ConsumptionResult  $result
     * @return string
     */
    private static function outcome(ConsumptionResult $result): string
    {
        return $result->isConsumed() || $result->isReplayed() ? $result->status->value : $result->status->value . ':' . $result->reason?->value;
    }
}
