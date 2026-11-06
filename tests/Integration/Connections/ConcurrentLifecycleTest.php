<?php

declare(strict_types = 1);

namespace Tests\Integration\Connections;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Races a disable and a trust change against the flows in flight through the
 * connection, across processes, each with its own database connection, on
 * PostgreSQL and MySQL (SSO-2.11, SSO-2.13, SSO-9.2):
 *
 * - a disable racing a completion that has consumed its request: either the
 *   completion commits a code first and the disable voids it, or the disable
 *   commits first and the completion fails with `connection_unavailable`;
 * - a disable racing a redemption: either the code is redeemed before the
 *   disable, which then leaves it, or the disable voids it first and the
 *   redemption is refused (`handoff_unknown` or `connection_unavailable`);
 * - a trust change racing a completion: as a disable does.
 *
 * However the racers interleave, no code is left neither redeemed nor voided
 * once both finish, and none is redeemed after a disable committed. Each race
 * runs with every process plain, and again with each inside a transaction of
 * its own that read the connection, its requests and its codes before the race
 * began, so a locking read must see what another process committed rather than
 * its transaction's snapshot (MySQL's `REPEATABLE READ`). A completion runs
 * outside any transaction on the storage connection, so a completing process is
 * always plain, and only the change it races runs inside one.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionLifecycle::class)]
#[CoversClass(ConnectionService::class)]
#[CoversClass(InFlightVoider::class)]
final class ConcurrentLifecycleTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var string The tenant the connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var string The protocol state the request was started with. */
    private const string STATE = 'the-protocol-state-of-the-raced-lifecycle-1';

    /** @var string The client's verifier (RFC 7636, appendix B). */
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /** @var string The S256 challenge of the client's verifier. */
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /** @var int Microseconds the driver takes to validate a response. */
    private const int VALIDATION_MICROSECONDS = 600000;

    /** @var float Seconds after the start the change begins, while the completion validates. */
    private const float CHANGE_DELAY = 0.2;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the flows run through. */
    private Connection $connection;

    /** @var \Tests\Fixtures\Protocols\VerifyingDriver The driver the connection runs over. */
    private VerifyingDriver $driver;

    /** @var string Directory the processes report their outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, bind a fixed clock, a
     * fresh caller, a limiter that allows every attempt and a linker that links
     * every result to one identity, register the application and the driver,
     * create the tables and the connection, and make the directory the
     * processes report in.
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

        $this->driver = new VerifyingDriver;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
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
             * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
            {
                unset($result);

                return ExampleLinks::resolution(new IdentityReference('App\Models\User', '42'));
            }
        });

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', [
            'web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
        ]);

        $driver = $this->driver;

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);
        $this->outcomes   = sys_get_temp_dir() . '/lifecycle-race-' . bin2hex(random_bytes(8));

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
     * A disable racing a completion that has consumed its request, each process
     * plain.
     *
     * @return void
     */
    public function testADisableRacingACompletionLeavesNoCodeUnvoided(): void
    {
        $this->assertCompletionRace($this->raceCompletion($this->disabler(), false), 'disabled');
    }

    /**
     * The same race, the disable inside a transaction of its own.
     *
     * @return void
     */
    public function testADisableRacingACompletionInsideCallersTransactionsLeavesNoCodeUnvoided(): void
    {
        $this->assertCompletionRace($this->raceCompletion($this->disabler(), true), 'disabled');
    }

    /**
     * A trust change racing a completion that has consumed its request, each
     * process plain.
     *
     * @return void
     */
    public function testATrustChangeRacingACompletionLeavesNoCodeUnvoided(): void
    {
        $this->assertCompletionRace($this->raceCompletion($this->trustChanger(), false), 'updated');
    }

    /**
     * The same race, the trust change inside a transaction of its own.
     *
     * @return void
     */
    public function testATrustChangeRacingACompletionInsideCallersTransactionsLeavesNoCodeUnvoided(): void
    {
        $this->assertCompletionRace($this->raceCompletion($this->trustChanger(), true), 'updated');
    }

    /**
     * A disable racing a redemption, each process plain.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testADisableRacingARedemptionNeverRedeemsAfterIt(): void
    {
        $this->assertRedemptionRace(false);
    }

    /**
     * The same race, each process inside a transaction of its own.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testADisableRacingARedemptionInsideCallersTransactionsNeverRedeemsAfterIt(): void
    {
        $this->assertRedemptionRace(true);
    }

    /**
     * Start a request, then race its completion, whose driver validates slowly,
     * against the change, begun while the completion validates, plain or inside
     * a transaction of its own; the completion is always plain.
     *
     * @param  \Closure(): string  $change
     * @param  bool  $inTransaction
     * @return list<string>
     */
    private function raceCompletion(\Closure $change, bool $inTransaction): array
    {
        $this->makeAuthorizationRequest($this->connection, [
            'state_digest'      => hash('sha256', self::STATE),
            'handoff_challenge' => self::CHALLENGE,
            'code_verifier'     => app(SecretEncrypter::class)->encrypt('the-pkce-verifier-of-the-raced-lifecycle-1'),
        ]);

        $this->driver->onComplete = static function (): void {
            usleep(self::VALIDATION_MICROSECONDS);
        };

        return $this->race([[0.0, $this->completer(), false], [self::CHANGE_DELAY, $change, $inTransaction]]);
    }

    /**
     * Assert the completion and the change ended in one of the two orders the
     * connection's lock allows, and no code is left neither redeemed nor
     * voided: a code issued first is voided by the change; a change made first
     * fails the completion and issues none.
     *
     * @param  list<string>  $outcomes
     * @param  string  $changed
     * @return void
     */
    private function assertCompletionRace(array $outcomes, string $changed): void
    {
        $listed = implode(', ', $outcomes);

        self::assertContains($outcomes, [['completed:-', $changed], ['failed:connection_unavailable', $changed]], $listed);
        self::assertSame(0, HandoffCode::query()->whereNull('voided_at')->whereNull('redeemed_at')->count(), $listed);
        self::assertSame($outcomes[0] === 'completed:-' ? 1 : 0, HandoffCode::query()->count(), $listed);
        self::assertNotNull(AuthorizationRequest::query()->sole()->completed_at, $listed);
    }

    /**
     * Issue a code, then race its redemption against a disable begun at the
     * same moment, and assert the code ended either redeemed and not voided,
     * the redemption having succeeded before the disable, or voided and not
     * redeemed, the redemption refused.
     *
     * @param  bool  $inTransaction
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function assertRedemptionRace(bool $inTransaction): void
    {
        $code     = $this->issue();
        $outcomes = $this->race([[0.0, $this->redeemer($code), $inTransaction], [0.0, $this->disabler(), $inTransaction]]);
        $listed   = implode(', ', $outcomes);
        $row      = HandoffCode::query()->sole();

        self::assertContains($outcomes[0], ['redeemed', 'refused:handoff_unknown', 'refused:connection_unavailable'], $listed);
        self::assertSame('disabled', $outcomes[1], $listed);
        self::assertSame($outcomes[0] === 'redeemed', $row->redeemed_at !== null, $listed);
        self::assertSame($row->redeemed_at === null, $row->voided_at !== null, $listed);
        self::assertFalse(Connection::query()->whereKey($this->connection->id)->sole()->enabled);
    }

    /**
     * What a completing process does: complete at the callback with the state
     * and report how it ended.
     *
     * @return \Closure(): string
     */
    private function completer(): \Closure
    {
        $connectionId = $this->connection->id;

        return static function () use ($connectionId): string {
            $result = app(CompletionService::class)->complete(
                CompletionEndpoint::CALLBACK,
                $connectionId,
                new CompletionRequest('GET', 'state=' . self::STATE, []),
                Clients::browser(),
            );

            return sprintf('%s:%s', $result->status->value, $result->reason->value ?? '-');
        };
    }

    /**
     * What a redeeming process does: redeem the code and report how it ended.
     *
     * @param  string  $code
     * @return \Closure(): string
     */
    private function redeemer(#[\SensitiveParameter] string $code): \Closure
    {
        $connectionId = $this->connection->id;

        return static function () use ($connectionId, $code): string {
            $answer = DB::connection(StorageConnection::name())->transaction(
                static fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $connectionId, $code, self::VERIFIER, Clients::browser()),
            );

            return $answer->isRedeemed() ? 'redeemed' : 'refused:' . $answer->reason?->value;
        };
    }

    /**
     * What a disabling process does: disable the connection and report the
     * outcome.
     *
     * @return \Closure(): string
     */
    private function disabler(): \Closure
    {
        $connectionId = $this->connection->id;

        return static fn (): string => app(ConnectionLifecycle::class)->disable(self::TENANT, $connectionId, Clients::browser())->status->value;
    }

    /**
     * What a process changing the connection's trust does: change its issuer
     * and report the outcome.
     *
     * @return \Closure(): string
     */
    private function trustChanger(): \Closure
    {
        $connectionId = $this->connection->id;

        return static fn (): string => app(ConnectionService::class)->update(
            self::TENANT,
            $connectionId,
            ['settings' => ['issuer' => 'https://login.example.com']],
            Clients::browser(),
        )->status->value;
    }

    /**
     * Fork a process for each racer, have each start its work at the start plus
     * its delay on a connection of its own, plain or inside a transaction of
     * its own, and collect what each reported, in the racers' order.
     *
     * @param  list<array{0: float, 1: \Closure(): string, 2: bool}>  $racers
     * @return list<string>
     */
    private function race(array $racers): array
    {
        DB::disconnect();

        $start = microtime(true) + 0.5;
        $pids  = [];

        foreach ($racers as $process => [$delay, $work, $inTransaction]) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $start + $delay, $work, $inTransaction);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        $outcomes = [];

        foreach (array_keys($racers) as $process) {
            $outcomes[] = (string) file_get_contents("{$this->outcomes}/{$process}");
        }

        return $outcomes;
    }

    /**
     * In a forked process: open a connection of its own, wait for its start, do
     * its work, report the outcome, and end without running the parent's
     * shutdown.
     *
     * Racing inside a transaction, the process opens one and reads the
     * connection, its requests and its codes before the start, so the
     * transaction's snapshot predates every other process's work, and commits
     * after its own.
     *
     * @param  int  $process
     * @param  float  $start
     * @param  \Closure(): string  $work
     * @param  bool  $inTransaction
     * @return never
     */
    private function runInChild(int $process, float $start, \Closure $work, bool $inTransaction): never
    {
        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            $database = DB::connection(StorageConnection::name());

            if ($inTransaction) {
                $database->beginTransaction();
                Connection::query()->whereKey($this->connection->id)->get();
                AuthorizationRequest::query()->where('connection_id', $this->connection->id)->get();
                HandoffCode::query()->where('connection_id', $this->connection->id)->get();
            }

            $wait = $start - microtime(true);

            if ($wait > 0) {
                usleep((int) ($wait * 1000000));
            }

            $outcome = $work();

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
            tenantId: self::TENANT,
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
            challenge: S256Challenge::fromString(self::CHALLENGE),
            expiresAt: CarbonImmutable::parse('2026-11-01T09:31:00Z'),
            trustVersion: $this->connection->trust_version,
            linkedIdentity: new IdentityReference('App\Models\User', '42'),
            linkId: 'link-42',
        );

        return app(DatabaseHandoffStore::class)->issue($grant)->code->reveal();
    }
}
