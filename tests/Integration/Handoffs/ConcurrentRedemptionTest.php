<?php

declare(strict_types = 1);

namespace Tests\Integration\Handoffs;

use Carbon\CarbonImmutable;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Races redemptions of one handoff code across processes, each with its own
 * database connection, on PostgreSQL and MySQL (SSO-9.2, SSO-11.3, SSO-11.5):
 * however they interleave, exactly one redeems the code and every other is
 * refused as `replayed`; the code is consumed once, recorded once in the
 * single-use store, and its connection's completed sign-in acknowledged.
 *
 * The race runs with every process plain, and again with each inside a
 * transaction of its own that read the code and its connection before the race
 * began, so each locking read must see what another process committed rather
 * than its transaction's snapshot (MySQL's `REPEATABLE READ`), and the locks a
 * caller's transaction keeps until it commits must hold the others off.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRedemption::class)]
final class ConcurrentRedemptionTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var int Processes racing to redeem one code. */
    private const int REDEEMERS = 4;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The client's verifier (RFC 7636, appendix B). */
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the code was issued through. */
    private Connection $connection;

    /** @var string The code every process races to redeem. */
    private string $code;

    /** @var string Directory the processes report their outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, bind a fixed clock, a
     * limiter that allows every attempt and a linker that links every result to
     * one identity, register the driver, create the tables, the connection and
     * the code, and make the directory the processes report in.
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
        $this->app?->instance(AttemptLimiter::class, new readonly class implements AttemptLimiter {
            /**
             * Allow every attempt.
             *
             * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject  $subject
             * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptResult
             */
            #[\Override]
            public function attempt(AttemptSubject $subject): AttemptResult
            {
                unset($subject);

                return AttemptResult::allowed();
            }
        });
        $this->app?->instance(Linker::class, new readonly class implements Linker {
            /**
             * One identity for every result.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
             */
            #[\Override]
            public function resolve(VerifiedResult $result): IdentityReference
            {
                unset($result);

                return new IdentityReference('App\Models\User', '42');
            }
        });

        $driver = new VerifyingDriver;

        config()->set('sso.features.oidc', true);

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->createConnectionTables();
        $this->createFlowTables();
        self::singleUseMigration()->up(); // @phpstan-ignore method.notFound

        $this->connection = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);
        $this->code       = $this->issue();
        $this->outcomes   = sys_get_temp_dir() . '/redemption-race-' . bin2hex(random_bytes(8));

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

        if (isset($this->code)) {
            self::singleUseMigration()->down(); // @phpstan-ignore method.notFound
            $this->dropFlowTables();
            $this->dropConnectionTables();
        }

        parent::tearDown();
    }

    /**
     * Redemptions of one code: exactly one redeems it, and every other is
     * refused as `replayed`.
     *
     * @return void
     */
    public function testExactlyOneOfTheRedemptionsOfOneCodeRedeemsIt(): void
    {
        $this->assertRedeemedOnce($this->race(false));
    }

    /**
     * The same race, each inside a transaction of its own that read the code
     * and its connection before the race began.
     *
     * @return void
     */
    public function testExactlyOneOfTheRedemptionsInsideACallersTransactionRedeemsIt(): void
    {
        $this->assertRedeemedOnce($this->race(true));
    }

    /**
     * Assert exactly one process redeemed the code, every other was refused as
     * `replayed`, and the code is consumed, recorded once, and its connection's
     * sign-in acknowledged.
     *
     * @param  list<string>  $outcomes
     * @return void
     */
    private function assertRedeemedOnce(array $outcomes): void
    {
        $listed = implode(', ', $outcomes);

        self::assertCount(1, array_keys($outcomes, 'redeemed', true), $listed);
        self::assertCount(self::REDEEMERS - 1, array_keys($outcomes, 'refused:replayed', true), $listed);
        self::assertNotNull(StoredCode::query()->where('code_digest', hash('sha256', $this->code))->sole()->redeemed_at);
        self::assertSame(1, DB::table(StorageConnection::table('single_use.table'))->count());
        self::assertTrue(Connection::query()->whereKey($this->connection->id)->sole()->has_completed_sign_in);
    }

    /**
     * Fork a redeeming process for each racer, have each start at the same
     * moment on a connection of its own, and collect what each reported.
     *
     * @param  bool  $inTransaction
     * @return list<string>
     */
    private function race(bool $inTransaction): array
    {
        DB::disconnect();

        $start = microtime(true) + 0.5;
        $pids  = [];

        for ($process = 0; $process < self::REDEEMERS; $process++) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $start, $inTransaction);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        $outcomes = [];

        for ($process = 0; $process < self::REDEEMERS; $process++) {
            $outcomes[] = (string) file_get_contents("{$this->outcomes}/{$process}");
        }

        return $outcomes;
    }

    /**
     * In a forked process: open a connection of its own, wait for the start,
     * redeem the code, report the outcome, and end without running the parent's
     * shutdown.
     *
     * Racing inside a transaction, the process opens one and reads the code and
     * its connection before the start, so the transaction's snapshot predates
     * every other process's work, and commits after its own.
     *
     * @param  int  $process
     * @param  float  $start
     * @param  bool  $inTransaction
     * @return never
     */
    private function runInChild(int $process, float $start, bool $inTransaction): never
    {
        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            $database = DB::connection(StorageConnection::name());

            if ($inTransaction) {
                $database->beginTransaction();
                StoredCode::query()->where('code_digest', hash('sha256', $this->code))->get();
                Connection::query()->whereKey($this->connection->id)->get();
            }

            $wait = $start - microtime(true);

            if ($wait > 0) {
                usleep((int) ($wait * 1000000));
            }

            $answer  = app(HandoffRedemption::class)->redeem(Purpose::SIGN_IN, 'web', $this->connection->id, $this->code, self::VERIFIER);
            $outcome = $answer->isRedeemed() ? 'redeemed' : 'refused:' . $answer->reason?->value;

            if ($inTransaction) {
                $database->commit();
            }
        } catch (\Throwable $e) {
            $outcome = 'error: ' . $e::class . ': ' . $e->getMessage();
        }

        file_put_contents("{$this->outcomes}/{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Issue a linked `sign_in` code for `web` through the connection, bound to
     * the client's verifier.
     *
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function issue(): string
    {
        $result = new VerifiedResult(
            issuer: VerifyingDriver::ISSUER,
            subject: VerifyingDriver::SUBJECT,
            nameIdFormat: null,
            connectionId: $this->connection->id,
            tenantId: 'tenant-1',
            protocol: VerifyingDriver::NAME,
            application: 'web',
            purpose: Purpose::SIGN_IN,
            requestReference: RequestReference::fromString('Gq8tVv3w0kLmNoPqRsTuVwXyZ0123456'),
            attributes: [],
            emailDomainVerified: false,
            authenticationContext: new AuthenticationContext(CarbonImmutable::parse('2026-11-01T09:29:00Z'), ['pwd']),
        );

        $grant = new HandoffGrant(
            result: $result,
            challenge: S256Challenge::fromString('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'),
            expiresAt: CarbonImmutable::parse('2026-11-01T09:31:00Z'),
            linkedIdentity: new IdentityReference('App\Models\User', '42'),
        );

        return app(DatabaseHandoffStore::class)->issue($grant)->code->reveal();
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
