<?php

declare(strict_types = 1);

namespace Tests\Feature\RateLimiting;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\RateLimiting\CounterKeys;
use SineMacula\Laravel\Sso\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptScope;
use SineMacula\Laravel\Sso\RateLimiting\RateLimitStore;
use Tests\Concerns\RunsInTimezone;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the default attempt limiter, on whichever engine the suite
 * runs against, with the shipped migration and a fixed clock: every attempt
 * counts up to the limit, a full limit refuses with the wait until its window
 * ends, all or none, each flow and scope counted apart, values counted in their
 * canonical form under keyed digests, and database errors propagated.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAttemptLimiter::class)]
#[CoversClass(RateLimitStore::class)]
final class DatabaseAttemptLimiterTest extends TestCase
{
    use RunsInTimezone;

    /** @var string Absolute path to the shipped rate limits migration. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var string The table's default name. */
    private const string TABLE = 'sso_rate_limits';

    /** @var string The separate connection the counters are moved to. */
    private const string COUNTERS = 'counters';

    /** @var string An IP address the tests count. */
    private const string IP = '203.0.113.7';

    /** @var string Another IP address the tests count. */
    private const string OTHER_IP = '198.51.100.20';

    /** @var string An email domain the tests count. */
    private const string DOMAIN = 'example.com';

    /** @var string A connection id the tests count. */
    private const string CONNECTION = 'connection-1';

    /** @var \Tests\Fixtures\FixedClock The clock the limiter reads, 15 seconds into a minute and an hour. */
    private FixedClock $clock;

    /**
     * Bind the fixed clock, 15 seconds after 12:00, and give the test the
     * package's tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-10-31T12:00:15Z');

        $this->app?->instance(Clock::class, $this->clock);

        $this->usePackageTables();
    }

    /**
     * In the last hour before a daylight-saving fall-back, a live window is
     * still live: at 00:30 UTC (01:30 BST) the hour-long window ending at 01:00
     * UTC (01:00 GMT) refuses the attempt past the limit, though in London's
     * wall-clock time its end reads as earlier than now. A stored window read
     * back, once the limit's window is shortened, is the same instant.
     *
     * @return void
     */
    public function testKeepsAWindowThroughADaylightSavingFallBack(): void
    {
        $this->inTimezone('Europe/London', function (): void {
            $this->clock = new FixedClock('2026-10-25T00:30:00Z');

            $this->app?->instance(Clock::class, $this->clock);
            $this->app?->forgetScopedInstances();
            $this->limit('redemption.per_ip', 3, 3600);

            $subject = AttemptSubject::redemption(self::IP);

            foreach (range(1, 3) as $attempt) {
                self::assertTrue($this->limiter()->attempt($subject)->isAllowed(), "Attempt {$attempt} should be allowed.");
            }

            self::assertSame(1800, $this->limiter()->attempt($subject)->retryAfter);
            self::assertSame('2026-10-25 01:00:00', $this->windowOf(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, self::IP));

            $this->limit('redemption.per_ip', 3, 60);

            self::assertSame(1800, $this->limiter()->attempt($subject)->retryAfter);
            self::assertSame(3, $this->hits(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, self::IP));
        });
    }

    /**
     * The container's attempt limiter is the default.
     *
     * @return void
     */
    public function testIsTheContainersAttemptLimiter(): void
    {
        self::assertInstanceOf(DatabaseAttemptLimiter::class, $this->limiter());
    }

    /**
     * Attempts are allowed up to the limit; the next is refused with the
     * seconds until the window ends, and is not counted.
     *
     * @return void
     */
    public function testAllowsUpToTheLimitThenRefusesWithTheWait(): void
    {
        $this->limit('redemption.per_ip', 3, 60);

        $subject = AttemptSubject::redemption(self::IP);

        foreach (range(1, 3) as $attempt) {
            self::assertTrue($this->limiter()->attempt($subject)->isAllowed(), "Attempt {$attempt} should be allowed.");
        }

        $refused = $this->limiter()->attempt($subject);

        self::assertTrue($refused->isRateLimited());
        self::assertFalse($refused->isAllowed());
        self::assertSame(FailureReason::RATE_LIMITED, $refused->reason);
        self::assertSame(45, $refused->retryAfter);
        self::assertSame(3, $this->hits(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, self::IP));
        self::assertSame('2026-10-31 12:01:00', $this->windowOf(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, self::IP));
    }

    /**
     * The wait counts down to the window's end, and once the clock passes it
     * the counter starts a new window with the attempt.
     *
     * @return void
     */
    public function testAllowsAgainOnceTheWindowHasEnded(): void
    {
        $this->limit('redemption.per_ip', 1, 60);

        $subject = AttemptSubject::redemption(self::IP);

        self::assertTrue($this->limiter()->attempt($subject)->isAllowed());

        $this->clock->advance(44);

        self::assertSame(1, $this->limiter()->attempt($subject)->retryAfter);

        $this->clock->advance(1);

        self::assertTrue($this->limiter()->attempt($subject)->isAllowed());
        self::assertSame(1, $this->hits(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, self::IP));
        self::assertSame('2026-10-31 12:02:00', $this->windowOf(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, self::IP));
        self::assertSame(60, $this->limiter()->attempt($subject)->retryAfter);
    }

    /**
     * All or none: with the IP address's limit full and the email domain's
     * free, the attempt is refused and the domain's counter is not touched.
     *
     * @return void
     */
    public function testAFullIpLimitCountsNothingAgainstTheEmailDomain(): void
    {
        $this->limit('authorization_request.per_ip', 1, 60);

        self::assertTrue($this->limiter()->attempt(AttemptSubject::authorizationRequest(self::IP, self::DOMAIN))->isAllowed());

        $refused = $this->limiter()->attempt(AttemptSubject::authorizationRequest(self::IP, 'example.org'));

        self::assertSame(45, $refused->retryAfter);
        self::assertSame(1, $this->hits(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_IP, self::IP));
        self::assertSame(1, $this->hits(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_EMAIL_DOMAIN, self::DOMAIN));
        self::assertNull($this->hits(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_EMAIL_DOMAIN, 'example.org'));
    }

    /**
     * All or none: with the email domain's limit full, the slot already taken
     * from the IP address's counter is given back, and the wait is the
     * domain's.
     *
     * @return void
     */
    public function testAFullEmailDomainLimitGivesTheIpSlotBack(): void
    {
        $this->limit('authorization_request.per_email_domain', 1, 3600);

        self::assertTrue($this->limiter()->attempt(AttemptSubject::authorizationRequest(self::IP, self::DOMAIN))->isAllowed());

        $refused = $this->limiter()->attempt(AttemptSubject::authorizationRequest(self::OTHER_IP, self::DOMAIN));

        self::assertSame(3585, $refused->retryAfter);
        self::assertSame(0, $this->hits(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_IP, self::OTHER_IP));
        self::assertSame(1, $this->hits(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_IP, self::IP));
        self::assertSame(1, $this->hits(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_EMAIL_DOMAIN, self::DOMAIN));
    }

    /**
     * All or none at a completion: a full connection limit gives the IP
     * address's slot back.
     *
     * @return void
     */
    public function testAFullConnectionLimitGivesTheIpSlotBack(): void
    {
        $this->limit('completion.per_connection', 2, 60);

        $this->limiter()->attempt(AttemptSubject::completion(self::IP, self::CONNECTION));
        $this->limiter()->attempt(AttemptSubject::completion(null, self::CONNECTION));

        self::assertTrue($this->limiter()->attempt(AttemptSubject::completion(self::OTHER_IP, self::CONNECTION))->isRateLimited());
        self::assertSame(0, $this->hits(AttemptFlow::COMPLETION, AttemptScope::PER_IP, self::OTHER_IP));
        self::assertSame(1, $this->hits(AttemptFlow::COMPLETION, AttemptScope::PER_IP, self::IP));
        self::assertSame(2, $this->hits(AttemptFlow::COMPLETION, AttemptScope::PER_CONNECTION, self::CONNECTION));
    }

    /**
     * Each flow and each scope is counted apart: one that is full refuses
     * nothing of another.
     *
     * @return void
     */
    public function testCountsEachFlowAndScopeApart(): void
    {
        $this->limit('redemption.per_ip', 1, 60);
        $this->limit('metadata.per_connection', 1, 3600);

        $limiter = $this->limiter();

        self::assertTrue($limiter->attempt(AttemptSubject::redemption(self::IP))->isAllowed());
        self::assertTrue($limiter->attempt(AttemptSubject::redemption(self::IP))->isRateLimited());
        self::assertTrue($limiter->attempt(AttemptSubject::redemption(self::OTHER_IP))->isAllowed());
        self::assertTrue($limiter->attempt(AttemptSubject::completion(self::IP, self::CONNECTION))->isAllowed());
        self::assertTrue($limiter->attempt(AttemptSubject::authorizationRequest(self::IP, self::DOMAIN))->isAllowed());

        self::assertTrue($limiter->attempt(AttemptSubject::metadata(self::CONNECTION))->isAllowed());
        self::assertTrue($limiter->attempt(AttemptSubject::metadata(self::CONNECTION))->isRateLimited());
        self::assertTrue($limiter->attempt(AttemptSubject::metadata('connection-2'))->isAllowed());
        self::assertTrue($limiter->attempt(AttemptSubject::domainCheck(self::CONNECTION))->isAllowed());
        self::assertTrue($limiter->attempt(AttemptSubject::completion(self::OTHER_IP, self::CONNECTION))->isAllowed());

        self::assertSame(2, $this->hits(AttemptFlow::COMPLETION, AttemptScope::PER_CONNECTION, self::CONNECTION));
        self::assertSame(1, $this->hits(AttemptFlow::DOMAIN_CHECK, AttemptScope::PER_CONNECTION, self::CONNECTION));
        self::assertSame(1, $this->hits(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_IP, self::IP));
    }

    /**
     * A `null` IP address or email domain is not counted: the attempt is
     * counted against what the subject gives, and one that gives nothing is
     * allowed without a counter.
     *
     * @return void
     */
    public function testDoesNotCountANullIpOrEmailDomain(): void
    {
        $this->limit('redemption.per_ip', 1, 60);

        foreach (range(1, 3) as $attempt) {
            self::assertTrue($this->limiter()->attempt(AttemptSubject::redemption(null))->isAllowed(), "Attempt {$attempt} should be allowed.");
        }

        self::assertTrue($this->limiter()->attempt(AttemptSubject::authorizationRequest(null))->isAllowed());
        self::assertSame(0, DB::table(self::TABLE)->count());

        self::assertTrue($this->limiter()->attempt(AttemptSubject::completion(null, self::CONNECTION))->isAllowed());
        self::assertTrue($this->limiter()->attempt(AttemptSubject::authorizationRequest(null, self::DOMAIN))->isAllowed());

        self::assertSame(2, DB::table(self::TABLE)->count());
        self::assertSame(1, $this->hits(AttemptFlow::COMPLETION, AttemptScope::PER_CONNECTION, self::CONNECTION));
        self::assertSame(1, $this->hits(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_EMAIL_DOMAIN, self::DOMAIN));
    }

    /**
     * An IPv4 address carried in IPv6 counts with the IPv4 address, and IPv6
     * addresses in one /64 count together.
     *
     * @return void
     */
    public function testCountsAnIpAddressInItsCanonicalForm(): void
    {
        $this->limit('redemption.per_ip', 2, 60);

        $limiter = $this->limiter();

        self::assertTrue($limiter->attempt(AttemptSubject::redemption(self::IP))->isAllowed());
        self::assertTrue($limiter->attempt(AttemptSubject::redemption('::ffff:' . self::IP))->isAllowed());
        self::assertTrue($limiter->attempt(AttemptSubject::redemption('64:ff9b::' . self::IP))->isRateLimited());

        self::assertTrue($limiter->attempt(AttemptSubject::redemption('2001:db8:1:2::1'))->isAllowed());
        self::assertTrue($limiter->attempt(AttemptSubject::redemption('2001:db8:1:2:abcd::9'))->isAllowed());
        self::assertTrue($limiter->attempt(AttemptSubject::redemption('2001:DB8:1:2::FFFF'))->isRateLimited());
        self::assertTrue($limiter->attempt(AttemptSubject::redemption('2001:db8:1:3::1'))->isAllowed());
    }

    /**
     * An email domain's case, a trailing dot and its Unicode and ASCII forms
     * count together.
     *
     * @return void
     */
    public function testCountsAnEmailDomainInItsCanonicalForm(): void
    {
        $this->limit('authorization_request.per_email_domain', 2, 60);

        $limiter = $this->limiter();

        self::assertTrue($limiter->attempt(AttemptSubject::authorizationRequest(null, 'Bücher.example'))->isAllowed());
        self::assertTrue($limiter->attempt(AttemptSubject::authorizationRequest(null, 'xn--bcher-kva.example'))->isAllowed());
        self::assertTrue($limiter->attempt(AttemptSubject::authorizationRequest(null, 'BÜCHER.EXAMPLE.'))->isRateLimited());
        self::assertTrue($limiter->attempt(AttemptSubject::authorizationRequest(null, 'Example.COM.'))->isAllowed());
        self::assertSame(1, $this->hits(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_EMAIL_DOMAIN, self::DOMAIN));
    }

    /**
     * The table holds keyed digests and counts only: no IP address, email
     * domain or connection id, as given or in its canonical form.
     *
     * @return void
     */
    public function testTheTableHoldsNoRawValue(): void
    {
        $limiter = $this->limiter();

        $limiter->attempt(AttemptSubject::authorizationRequest('2001:db8:1:2::1', 'Bücher.example'));
        $limiter->attempt(AttemptSubject::completion('::ffff:' . self::IP, 'tenant-connection'));
        $limiter->attempt(AttemptSubject::redemption(self::OTHER_IP));
        $limiter->attempt(AttemptSubject::metadata('tenant-connection'));
        $limiter->attempt(AttemptSubject::domainCheck('tenant-connection'));

        $rows = DB::table(self::TABLE)->get()->map(static fn (object $row): array => (array) $row)->all();

        self::assertCount(7, $rows);

        $dump = strtolower((string) json_encode($rows, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));

        $values = ['2001:db8', 'bücher', 'bcher', 'xn--', '203.0.113', self::OTHER_IP, '::ffff', 'tenant-connection', 'example'];

        foreach ($values as $value) {
            self::assertStringNotContainsString($value, $dump);
        }

        foreach ($rows as $row) {
            self::assertIsString($row['key']);
            self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $row['key']);
        }
    }

    /**
     * A malformed limit fails closed before anything is counted, even for a
     * subject whose value for that scope is not given.
     *
     * @return void
     */
    public function testAMalformedLimitFailsClosedAndCountsNothing(): void
    {
        config()->set('sso.rate_limits.completion.per_ip', null);

        try {
            $this->limiter()->attempt(AttemptSubject::completion(null, self::CONNECTION));

            self::fail('Expected the malformed limit to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('`sso.rate_limits.completion.per_ip`', $exception->getMessage());
        }

        self::assertSame(0, DB::table(self::TABLE)->count());
    }

    /**
     * A database error propagates: a limiter that cannot count lets nothing
     * through.
     *
     * @return void
     */
    public function testADatabaseErrorPropagates(): void
    {
        Schema::drop(self::TABLE);

        $this->expectException(QueryException::class);

        $this->limiter()->attempt(AttemptSubject::redemption(self::IP));
    }

    /**
     * A counter whose window was started under a longer `decay_seconds` keeps
     * that window until it ends: full, it refuses until then; with room, it is
     * counted in.
     *
     * @return void
     */
    public function testAStoredWindowIsKeptUntilItEnds(): void
    {
        $this->limit('redemption.per_ip', 2, 3600);

        $subject = AttemptSubject::redemption(self::IP);

        $this->limiter()->attempt($subject);
        $this->limiter()->attempt($subject);

        $this->limit('redemption.per_ip', 2, 60);

        self::assertSame(3585, $this->limiter()->attempt($subject)->retryAfter);

        $this->limit('redemption.per_ip', 3, 60);

        self::assertTrue($this->limiter()->attempt($subject)->isAllowed());
        self::assertSame(3585, $this->limiter()->attempt($subject)->retryAfter);
        self::assertSame(3, $this->hits(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, self::IP));
        self::assertSame('2026-10-31 13:00:00', $this->windowOf(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, self::IP));
    }

    /**
     * A slot taken from a stored window is given back to that window when a
     * later limit is full.
     *
     * @return void
     */
    public function testASlotTakenFromAStoredWindowGoesBackToIt(): void
    {
        $this->limit('authorization_request.per_ip', 5, 3600);

        $this->limiter()->attempt(AttemptSubject::authorizationRequest(self::IP));

        $this->limit('authorization_request.per_ip', 5, 60);
        $this->limit('authorization_request.per_email_domain', 1, 60);

        $this->limiter()->attempt(AttemptSubject::authorizationRequest(self::OTHER_IP, self::DOMAIN));

        self::assertSame(45, $this->limiter()->attempt(AttemptSubject::authorizationRequest(self::IP, self::DOMAIN))->retryAfter);
        self::assertSame(1, $this->hits(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_IP, self::IP));
        self::assertSame('2026-10-31 13:00:00', $this->windowOf(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_IP, self::IP));
    }

    /**
     * A slot is given back only to the window it was taken from: a counter that
     * has moved on to another window keeps its count.
     *
     * @return void
     */
    public function testAGiveBackLeavesAnotherWindowAlone(): void
    {
        $this->limit('authorization_request.per_email_domain', 1, 60);

        $this->limiter()->attempt(AttemptSubject::authorizationRequest(self::OTHER_IP, self::DOMAIN));

        $key = $this->key(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_IP, self::IP);

        $this->beforeFirst('/^update .* - 1/i', static function () use ($key): void {
            DB::table(self::TABLE)->where('key', $key)->update(['hits' => 7, 'window_ends_at' => '2026-10-31 12:02:00']);
        });

        self::assertTrue($this->limiter()->attempt(AttemptSubject::authorizationRequest(self::IP, self::DOMAIN))->isRateLimited());
        self::assertSame(7, $this->hits(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_IP, self::IP));
    }

    /**
     * A counter created by another request between this one's update and its
     * insert is counted in by the update that follows.
     *
     * @return void
     */
    public function testACounterCreatedConcurrentlyIsCountedOnRetry(): void
    {
        $key = $this->key(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, self::IP);

        $this->beforeFirst('/^insert/i', static function () use ($key): void {
            DB::table(self::TABLE)->insert(['key' => $key, 'hits' => 1, 'window_ends_at' => '2026-10-31 12:01:00']);
        });

        self::assertTrue($this->limiter()->attempt(AttemptSubject::redemption(self::IP))->isAllowed());
        self::assertSame(2, $this->hits(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, self::IP));
    }

    /**
     * A counter that ends or goes before it is read refuses the attempt for one
     * second, rather than letting it through uncounted.
     *
     * @return void
     */
    public function testACounterGoneBeforeItIsReadRefusesForOneSecond(): void
    {
        $this->fillAStoredWindow(1);

        $this->beforeFirst('/^select/i', static function (): void {
            DB::table(self::TABLE)->delete();
        });

        self::assertSame(1, $this->limiter()->attempt(AttemptSubject::redemption(self::IP))->retryAfter);
    }

    /**
     * A counter whose stored window ended before it was read refuses for one
     * second too.
     *
     * @return void
     */
    public function testACounterEndedBeforeItIsReadRefusesForOneSecond(): void
    {
        $this->fillAStoredWindow(1);

        $this->beforeFirst('/^select/i', static function (): void {
            DB::table(self::TABLE)->update(['window_ends_at' => '2026-10-31 12:00:15']);
        });

        self::assertSame(1, $this->limiter()->attempt(AttemptSubject::redemption(self::IP))->retryAfter);
    }

    /**
     * A stored window filled by another request before it is read refuses the
     * attempt until it ends.
     *
     * @return void
     */
    public function testAStoredWindowFilledBeforeItIsReadRefuses(): void
    {
        $this->fillAStoredWindow(2, 1);

        $this->beforeFirst('/^select/i', static function (): void {
            DB::table(self::TABLE)->update(['hits' => 2]);
        });

        self::assertSame(3585, $this->limiter()->attempt(AttemptSubject::redemption(self::IP))->retryAfter);
        self::assertSame(2, $this->hits(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, self::IP));
    }

    /**
     * A stored window filled by another request between this one's read and its
     * increment refuses the attempt until it ends, without exceeding the limit.
     *
     * @return void
     */
    public function testAStoredWindowFilledBeforeTheIncrementRefuses(): void
    {
        $this->fillAStoredWindow(2, 1);

        $this->beforeFirst('/^update (?!.* case )/i', static function (): void {
            DB::table(self::TABLE)->update(['hits' => 2]);
        });

        self::assertSame(3585, $this->limiter()->attempt(AttemptSubject::redemption(self::IP))->retryAfter);
        self::assertSame(2, $this->hits(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, self::IP));
    }

    /**
     * With `sso.rate_limits.connection` set, the counters are read and written
     * on that connection, and the storage connection holds none.
     *
     * @return void
     */
    public function testCountsOnTheRateLimitsConnection(): void
    {
        Schema::dropIfExists(self::TABLE);

        config()->set('sso.rate_limits.connection', self::COUNTERS);

        $this->migration()->up(); // @phpstan-ignore method.notFound

        self::assertTrue($this->limiter()->attempt(AttemptSubject::completion(self::IP, self::CONNECTION))->isAllowed());

        self::assertSame(2, DB::connection(self::COUNTERS)->table(self::TABLE)->count());
        self::assertFalse(Schema::hasTable(self::TABLE));

        config()->set('sso.rate_limits.connection', null);
    }

    /**
     * Add the separate connection the counters are moved to.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('database.connections.' . self::COUNTERS, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
    }

    /**
     * Set one limit.
     *
     * @param  string  $limit
     * @param  int  $max
     * @param  int  $decay
     * @return void
     */
    private function limit(string $limit, int $max, int $decay): void
    {
        config()->set('sso.rate_limits.' . $limit, ['max' => $max, 'decay_seconds' => $decay]);
    }

    /**
     * Start the IP address's redemption counter in an hour-long window with the
     * attempts given, then shorten the limit's window to a minute, so the
     * stored window no longer ends where the limiter computes.
     *
     * @param  int  $max
     * @param  int  $attempts
     * @return void
     */
    private function fillAStoredWindow(int $max, int $attempts = 1): void
    {
        $this->limit('redemption.per_ip', $max, 3600);

        for ($attempt = 0; $attempt < $attempts; $attempt++) {
            $this->limiter()->attempt(AttemptSubject::redemption(self::IP));
        }

        $this->limit('redemption.per_ip', $max, 60);
    }

    /**
     * Run the callback once, just before the first statement on the default
     * connection matching the pattern, as another request would between two of
     * the limiter's.
     *
     * @param  string  $pattern
     * @param  \Closure(): mixed  $callback
     * @return void
     */
    private function beforeFirst(string $pattern, \Closure $callback): void
    {
        $ran = false;

        DB::connection()->beforeExecuting(static function (string $query) use (&$ran, $pattern, $callback): void {
            if ($ran || preg_match($pattern, $query) !== 1) {
                return;
            }

            $ran = true;

            $callback();
        });
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
     * The key of the counter for the flow, scope and value.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow  $flow
     * @param  \SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptScope  $scope
     * @param  string  $value
     * @return string
     */
    private function key(AttemptFlow $flow, AttemptScope $scope, string $value): string
    {
        $keys = $this->app?->make(CounterKeys::class);

        self::assertInstanceOf(CounterKeys::class, $keys);

        return $keys->counter($flow, $scope, $value);
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
        $hits = DB::table(self::TABLE)->where('key', $this->key($flow, $scope, $value))->value('hits');

        return is_numeric($hits) ? (int) $hits : null;
    }

    /**
     * The end of the counter's stored window, or `null` when there is no
     * counter.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow  $flow
     * @param  \SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptScope  $scope
     * @param  string  $value
     * @return ?string
     */
    private function windowOf(AttemptFlow $flow, AttemptScope $scope, string $value): ?string
    {
        $window = DB::table(self::TABLE)->where('key', $this->key($flow, $scope, $value))->value('window_ends_at');

        return is_string($window) ? $window : null;
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
            self::fail('The rate limits migration did not return a Migration instance.');
        }

        return $migration;
    }
}
