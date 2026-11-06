<?php

declare(strict_types = 1);

namespace Tests\Integration\Domains;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainFinder;
use SineMacula\Laravel\Sso\Domains\DomainResult;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Races claims and verifications of one domain across processes, each with its
 * own database connection, on PostgreSQL and MySQL (BL-20, SSO-3.2): however
 * they interleave, a domain claimed by many connections of many tenants is
 * verified for exactly one, the rest refused `domain_unavailable`; a claim one
 * connection verifies many times at once is verified once, the rest
 * `unchanged`; and a domain claimed many times by one connection is claimed
 * once, the rest duplicates. Each race runs with every process making its call
 * plainly, and again with each inside a transaction of its own that read the
 * domains before the race began, so a re-read that decides a write must see
 * what another process committed rather than its transaction's snapshot
 * (MySQL's `REPEATABLE READ`).
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainService::class)]
#[CoversClass(DomainFinder::class)]
final class ConcurrentDomainClaimsTest extends TestCase
{
    use UsesConnections;

    /** @var int Processes racing in each test. */
    private const int PROCESSES = 8;

    /** @var string The domain the processes race for. */
    private const string DOMAIN = 'example.com';

    /** @var list<\SineMacula\Laravel\Sso\Models\Connection> One connection per process, each of its own tenant. */
    private array $connections = [];

    /** @var string Directory the processes report their outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, bind a fixed clock, a
     * fresh caller and a fake resolver, create the tables, and make a
     * connection for each process.
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
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(DnsResolver::class, new FakeDnsResolver);

        config()->set('sso.rate_limits.domain_check.per_connection', ['max' => 1000, 'decay_seconds' => 3600]);

        $this->usePackageTables();

        for ($process = 0; $process < self::PROCESSES; $process++) {
            $this->connections[] = $this->makeConnection(['tenant_id' => 'tenant-' . $process]);
        }

        $this->outcomes = sys_get_temp_dir() . '/domain-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the outcomes.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (glob(($this->outcomes ?? sys_get_temp_dir() . '/none') . '/*') ?: [] as $file) {
            unlink($file);
        }

        if (isset($this->outcomes) && is_dir($this->outcomes)) {
            rmdir($this->outcomes);
        }

        parent::tearDown();
    }

    /**
     * Connections of different tenants racing to verify the domain each
     * claimed: exactly one verifies it, and the rest are refused.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacingVerificationsVerifiesTheDomain(): void
    {
        $this->claimForEveryConnection();

        $outcomes = $this->race(
            fn (DomainService $domains, Connection $connection): DomainResult => $domains->verify($connection->tenant_id, $connection->id, self::DOMAIN, Clients::browser()),
        );

        $this->assertExactlyOneVerified($outcomes);
    }

    /**
     * The same race, each verification inside a transaction of its own that
     * read the domain's claims before the race began.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacingVerificationsInsideACallersTransactionVerifiesTheDomain(): void
    {
        $this->claimForEveryConnection();

        $outcomes = $this->race(
            fn (DomainService $domains, Connection $connection): DomainResult => $domains->verify($connection->tenant_id, $connection->id, self::DOMAIN, Clients::browser()),
            true,
        );

        $this->assertExactlyOneVerified($outcomes);
    }

    /**
     * Processes racing to verify one connection's own claim of the domain:
     * exactly one verifies it, and the rest find it `unchanged`, judged again
     * under the lock when they passed the check made before the lookup.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacingVerificationsByOneConnectionVerifiesTheDomain(): void
    {
        $this->claimForOneConnection();

        $outcomes = $this->race(fn (DomainService $domains): DomainResult => $domains->verify('tenant-0', $this->connections[0]->id, self::DOMAIN, Clients::browser()));

        $this->assertVerifiedOnceAndOtherwiseUnchanged($outcomes);
    }

    /**
     * The same race, each verification inside a transaction of its own that
     * read the domain's claims before the race began.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacingVerificationsByOneConnectionInsideACallersTransactionVerifiesTheDomain(): void
    {
        $this->claimForOneConnection();

        $outcomes = $this->race(fn (DomainService $domains): DomainResult => $domains->verify('tenant-0', $this->connections[0]->id, self::DOMAIN, Clients::browser()), true);

        $this->assertVerifiedOnceAndOtherwiseUnchanged($outcomes);
    }

    /**
     * Processes racing to claim the domain for one connection: exactly one
     * claims it, and the rest are duplicates.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacingClaimsByOneConnectionClaimsTheDomain(): void
    {
        $outcomes = $this->race(fn (DomainService $domains): DomainResult => $domains->claim('tenant-0', $this->connections[0]->id, self::DOMAIN, Clients::browser()));

        $this->assertExactlyOneClaimed($outcomes);
    }

    /**
     * The same race, each claim inside a transaction of its own that read the
     * domain's claims before the race began.
     *
     * @return void
     */
    public function testExactlyOneOfTheRacingClaimsInsideACallersTransactionClaimsTheDomain(): void
    {
        $outcomes = $this->race(fn (DomainService $domains): DomainResult => $domains->claim('tenant-0', $this->connections[0]->id, self::DOMAIN, Clients::browser()), true);

        $this->assertExactlyOneClaimed($outcomes);
    }

    /**
     * Claim the domain for every connection, publish every claim's token at its
     * record name, and take each connection's first domain check, so its
     * counter exists before the race.
     *
     * @return void
     */
    private function claimForEveryConnection(): void
    {
        $tokens = [];

        foreach ($this->connections as $connection) {

            $result = $this->domains()->claim($connection->tenant_id, $connection->id, self::DOMAIN, Clients::browser());

            self::assertSame(DomainStatus::CLAIMED, $result->status);

            $tokens[] = $result->domain?->verificationToken() ?? '';

            $this->limiter()->attempt(AttemptSubject::domainCheck($connection->id));
        }

        /** @var \SineMacula\Laravel\Sso\Testing\FakeDnsResolver $dns */
        $dns = $this->app?->make(DnsResolver::class);

        $dns->found('_sso-verification.' . self::DOMAIN, ...$tokens);
    }

    /**
     * Claim the domain for the first connection alone, publish its token at its
     * record name, and take its first domain check, so its counter exists
     * before the race.
     *
     * @return void
     */
    private function claimForOneConnection(): void
    {
        $connection = $this->connections[0];
        $result     = $this->domains()->claim($connection->tenant_id, $connection->id, self::DOMAIN, Clients::browser());

        self::assertSame(DomainStatus::CLAIMED, $result->status);

        $this->limiter()->attempt(AttemptSubject::domainCheck($connection->id));

        /** @var \SineMacula\Laravel\Sso\Testing\FakeDnsResolver $dns */
        $dns = $this->app?->make(DnsResolver::class);

        $dns->found('_sso-verification.' . self::DOMAIN, $result->domain?->verificationToken() ?? '');
    }

    /**
     * Assert exactly one process verified the connection's claim, every other
     * found it `unchanged`, and the one claim holds the domain.
     *
     * @param  list<string>  $outcomes
     * @return void
     */
    private function assertVerifiedOnceAndOtherwiseUnchanged(array $outcomes): void
    {
        self::assertCount(1, array_keys($outcomes, DomainStatus::VERIFIED->value, true), implode(', ', $outcomes));
        self::assertCount(self::PROCESSES - 1, array_keys($outcomes, DomainStatus::UNCHANGED->value, true), implode(', ', $outcomes));
        self::assertSame(1, Domain::query()->count());
        self::assertSame(1, Domain::query()->where('verified_domain', self::DOMAIN)->count());
    }

    /**
     * Assert exactly one process verified the domain, every other was refused
     * `domain_unavailable`, and one claim holds it.
     *
     * @param  list<string>  $outcomes
     * @return void
     */
    private function assertExactlyOneVerified(array $outcomes): void
    {
        $refused = DomainStatus::REFUSED->value . ':' . FailureReason::DOMAIN_UNAVAILABLE->value;

        self::assertCount(1, array_keys($outcomes, DomainStatus::VERIFIED->value, true), implode(', ', $outcomes));
        self::assertCount(self::PROCESSES - 1, array_keys($outcomes, $refused, true), implode(', ', $outcomes));
        self::assertSame(1, Domain::query()->where('verified_domain', self::DOMAIN)->count());
        self::assertSame(1, Domain::query()->where('state', 'verified')->count());
    }

    /**
     * Assert exactly one process claimed the domain, every other found it a
     * duplicate, and one claim exists.
     *
     * @param  list<string>  $outcomes
     * @return void
     */
    private function assertExactlyOneClaimed(array $outcomes): void
    {
        $duplicate = DomainStatus::INVALID->value . ':' . FailureReason::SETTINGS_INVALID->value;

        self::assertCount(1, array_keys($outcomes, DomainStatus::CLAIMED->value, true), implode(', ', $outcomes));
        self::assertCount(self::PROCESSES - 1, array_keys($outcomes, $duplicate, true), implode(', ', $outcomes));
        self::assertSame(1, Domain::query()->count());
    }

    /**
     * Fork the processes, have each make its call at the same moment on a
     * connection of its own, and collect what each reported.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Domains\DomainService, \SineMacula\Laravel\Sso\Models\Connection): \SineMacula\Laravel\Sso\Domains\DomainResult  $call
     * @param  bool  $inTransaction
     * @return list<string>
     */
    private function race(\Closure $call, bool $inTransaction = false): array
    {
        DB::disconnect();

        $start = microtime(true) + 0.5;
        $pids  = [];

        for ($process = 0; $process < self::PROCESSES; $process++) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $start, $call, $inTransaction);
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
     * In a forked process: open a connection of its own and build the helpers,
     * so only the call's own work runs after the start, wait for the start,
     * make the call, report the outcome, and end without running the parent's
     * shutdown.
     *
     * Racing inside a transaction, the process opens one and reads the domain's
     * claims before the start, so the transaction's snapshot predates every
     * change, and commits after its own call.
     *
     * @param  int  $process
     * @param  float  $start
     * @param  \Closure(\SineMacula\Laravel\Sso\Domains\DomainService, \SineMacula\Laravel\Sso\Models\Connection): \SineMacula\Laravel\Sso\Domains\DomainResult  $call
     * @param  bool  $inTransaction
     * @return never
     */
    private function runInChild(int $process, float $start, \Closure $call, bool $inTransaction): never
    {
        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            $domains  = $this->domains();
            $database = DB::connection(StorageConnection::name());

            if ($inTransaction) {
                $database->beginTransaction();
                Domain::query()->where('domain', self::DOMAIN)->get();
            }

            $wait = $start - microtime(true);

            if ($wait > 0) {
                usleep((int) ($wait * 1000000));
            }

            $result = $call($domains, $this->connections[$process]);

            if ($inTransaction) {
                $database->commit();
            }

            $outcome = $result->reason === null || $result->isSucceeded() ? $result->status->value : $result->status->value . ':' . $result->reason->value;
        } catch (\Throwable $e) {
            $outcome = 'error: ' . $e->getMessage();
        }

        file_put_contents("{$this->outcomes}/{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * The domain helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Domains\DomainService
     */
    private function domains(): DomainService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DomainService::class);
    }

    /**
     * The attempt limiter, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\AttemptLimiter
     */
    private function limiter(): AttemptLimiter
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(AttemptLimiter::class);
    }
}
