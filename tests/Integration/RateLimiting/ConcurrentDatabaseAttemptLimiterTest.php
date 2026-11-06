<?php

declare(strict_types = 1);

namespace Tests\Integration\RateLimiting;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\RateLimiting\CounterKeys;
use SineMacula\Laravel\Sso\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptScope;
use SineMacula\Laravel\Sso\RateLimiting\RateLimitStore;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Races the default attempt limiter against itself across processes, each with
 * its own database connection, on PostgreSQL and MySQL: however the attempts
 * interleave, no more than the limit are allowed, and an attempt refused by one
 * limit counts nothing against another.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAttemptLimiter::class)]
#[CoversClass(RateLimitStore::class)]
final class ConcurrentDatabaseAttemptLimiterTest extends TestCase
{
    /** @var string The table's default name. */
    private const string TABLE = 'sso_rate_limits';

    /** @var int Processes racing in each test. */
    private const int PROCESSES = 12;

    /** @var int Attempts each limit allows in the window. */
    private const int MAX = 5;

    /** @var string The IP address every process attempts from. */
    private const string IP = '203.0.113.7';

    /** @var string The email domain every authorisation request gives. */
    private const string DOMAIN = 'example.com';

    /** @var \Tests\Fixtures\FixedClock The clock every process reads. */
    private FixedClock $clock;

    /** @var string Directory the processes report their outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, bind a fixed clock so
     * every process counts in the same window, and give the test the package's
     * tables.
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

        $this->clock = new FixedClock('2026-10-31T12:00:15Z');

        $this->app?->instance(Clock::class, $this->clock);

        $this->usePackageTables();

        $this->outcomes = sys_get_temp_dir() . '/sso-limiter-race-' . bin2hex(random_bytes(8));

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
     * Redemptions racing for one IP address's first window are allowed exactly
     * up to the limit, the counter's creation race included, and the counter
     * ends at the limit.
     *
     * @return void
     */
    public function testRacingRedemptionsNeverExceedTheLimit(): void
    {
        $outcomes = $this->race(static fn (AttemptLimiter $limiter): string => self::outcomeOf($limiter, AttemptSubject::redemption(new ClientContext(self::IP, null))));

        self::assertCount(self::MAX, array_keys($outcomes, 'allowed', true), implode(', ', $outcomes));
        self::assertCount(self::PROCESSES - self::MAX, array_keys($outcomes, 'rate_limited', true), implode(', ', $outcomes));
        self::assertSame(self::MAX, $this->hits(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, self::IP));
    }

    /**
     * Redemptions racing for a counter whose window has ended, and was full,
     * restart its window once between them: exactly up to the limit are
     * allowed, and the counter ends at the limit of the new window.
     *
     * @return void
     */
    public function testRacingRedemptionsRestartAnEndedWindowOnce(): void
    {
        for ($attempt = 0; $attempt < self::MAX; $attempt++) {
            $this->limiter()->attempt(AttemptSubject::redemption(new ClientContext(self::IP, null)));
        }

        $this->clock->advance(60);

        $outcomes = $this->race(static fn (AttemptLimiter $limiter): string => self::outcomeOf($limiter, AttemptSubject::redemption(new ClientContext(self::IP, null))));

        self::assertCount(self::MAX, array_keys($outcomes, 'allowed', true), implode(', ', $outcomes));
        self::assertCount(self::PROCESSES - self::MAX, array_keys($outcomes, 'rate_limited', true), implode(', ', $outcomes));
        self::assertSame(self::MAX, $this->hits(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, self::IP));
    }

    /**
     * Authorisation requests racing against a full IP address limit are all
     * refused, and never count against the email domain's free limit.
     *
     * @return void
     */
    public function testRacingRequestsAgainstAFullIpNeverCountTheDomain(): void
    {
        for ($attempt = 0; $attempt < self::MAX; $attempt++) {
            $this->limiter()->attempt(AttemptSubject::authorizationRequest(new ClientContext(self::IP, null)));
        }

        $outcomes = $this->race(
            static fn (AttemptLimiter $limiter): string => self::outcomeOf($limiter, AttemptSubject::authorizationRequest(new ClientContext(self::IP, null), self::DOMAIN)),
        );

        self::assertSame(array_fill(0, self::PROCESSES, 'rate_limited'), $outcomes);
        self::assertSame(self::MAX, $this->hits(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_IP, self::IP));
        self::assertNull($this->hits(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_EMAIL_DOMAIN, self::DOMAIN));
    }

    /**
     * Authorisation requests racing against a full email domain limit are all
     * refused, and every slot they took from their IP address's limit is given
     * back.
     *
     * The IP address's limit has room for every process and a two-minute
     * window, so every process takes an IP slot before it reaches the full
     * domain counter, and each refusal reports the domain window's wait (45
     * seconds to 12:01:00) rather than the IP window's (105 seconds to
     * 12:02:00): every refusal came from the domain, after a slot was taken.
     *
     * @return void
     */
    public function testRacingRequestsAgainstAFullDomainGiveEveryIpSlotBack(): void
    {
        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => self::PROCESSES, 'decay_seconds' => 120]);

        for ($attempt = 0; $attempt < self::MAX; $attempt++) {
            $this->limiter()->attempt(AttemptSubject::authorizationRequest(new ClientContext(null, null), self::DOMAIN));
        }

        $subject  = AttemptSubject::authorizationRequest(new ClientContext(self::IP, null), self::DOMAIN);
        $outcomes = $this->race(static fn (AttemptLimiter $limiter): string => self::outcomeOf($limiter, $subject, withWait: true));

        self::assertSame(array_fill(0, self::PROCESSES, 'rate_limited:45'), $outcomes);
        self::assertSame(0, $this->hits(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_IP, self::IP));
        self::assertSame(self::MAX, $this->hits(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_EMAIL_DOMAIN, self::DOMAIN));
    }

    /**
     * Limit every scope the tests race to `MAX` attempts a minute. The test of
     * the domain's give-back widens the IP address's limit for itself.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('sso.rate_limits.redemption.per_ip', ['max' => self::MAX, 'decay_seconds' => 60]);
        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => self::MAX, 'decay_seconds' => 60]);
        config()->set('sso.rate_limits.authorization_request.per_email_domain', ['max' => self::MAX, 'decay_seconds' => 60]);
    }

    /**
     * Fork the processes, have each reconnect and make the attempt at the same
     * moment on a connection of its own, and collect what each reported.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Contracts\AttemptLimiter): string  $attempt
     * @return list<string>
     */
    private function race(\Closure $attempt): array
    {
        DB::disconnect();

        $start = microtime(true) + 0.5;
        $pids  = [];

        for ($process = 0; $process < self::PROCESSES; $process++) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $start, $attempt);
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
     * In a forked process: open a connection of its own and resolve the
     * limiter, so only the attempt's own statements run after the start, wait
     * for the start, make the attempt, report its outcome, and end without
     * running the parent's shutdown.
     *
     * A process that reaches the start late, on a loaded machine, attempts at
     * once rather than failing: the race is then less close, but every
     * assertion still holds.
     *
     * @param  int  $process
     * @param  float  $start
     * @param  \Closure(\SineMacula\Laravel\Sso\Contracts\AttemptLimiter): string  $attempt
     * @return never
     */
    private function runInChild(int $process, float $start, \Closure $attempt): never
    {
        try {
            DB::reconnect();
            DB::connection()->getPdo();

            $limiter = $this->limiter();
            $wait    = $start - microtime(true);

            if ($wait > 0) {
                usleep((int) ($wait * 1000000));
            }

            $outcome = $attempt($limiter);
        } catch (\Throwable $e) {
            $outcome = 'error: ' . $e->getMessage();
        }

        file_put_contents("{$this->outcomes}/{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Make the attempt and name its outcome, with the wait a refusal reports
     * when asked.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject  $subject
     * @param  bool  $withWait
     * @return string
     */
    private static function outcomeOf(AttemptLimiter $limiter, AttemptSubject $subject, bool $withWait = false): string
    {
        $result = $limiter->attempt($subject);

        return match (true) {
            $result->isAllowed() => 'allowed',
            $withWait            => 'rate_limited:' . $result->retryAfter,
            default              => 'rate_limited',
        };
    }

    /**
     * The container's attempt limiter.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\AttemptLimiter
     */
    private function limiter(): AttemptLimiter
    {
        $limiter = $this->app?->make(AttemptLimiter::class);

        self::assertInstanceOf(AttemptLimiter::class, $limiter);

        return $limiter;
    }

    /**
     * The attempts the counter holds, or `null` when there is no counter.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow  $flow
     * @param  \SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptScope  $scope
     * @param  string  $value
     * @return ?int
     */
    private function hits(AttemptFlow $flow, AttemptScope $scope, string $value): ?int
    {
        $keys = $this->app?->make(CounterKeys::class);

        self::assertInstanceOf(CounterKeys::class, $keys);

        $hits = DB::table(self::TABLE)->where('key', $keys->counter($flow, $scope, $value))->value('hits');

        return is_numeric($hits) ? (int) $hits : null;
    }
}
