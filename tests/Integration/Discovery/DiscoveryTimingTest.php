<?php

declare(strict_types = 1);

namespace Tests\Integration\Discovery;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Discovery\DiscoveryService;
use SineMacula\Laravel\Sso\Discovery\Pacer;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Exceptions\InvalidConfigurationException;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\FlowsCheck;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Protocols\StartingDriver;
use Tests\TestCase;

/**
 * A match and a miss answer in the same time (SSO-3.5), on every database the
 * suite runs on: with the least time a discovery start takes set to 100 ms,
 * fifteen matches and fifteen misses, interleaved, each take at least 100 ms
 * and their medians differ by less than 15 ms, and still do when the identity
 * provider's driver is slow to start (30 ms). The pacer waits out the rest of
 * the floor and never less; an exception is not held; a floor below 50 ms fails
 * closed before anything is counted, and is refused at boot by `[flows]`
 * (`Tests\Feature\Flows\FlowsCheckTest::testTheRanges` checks the range
 * itself).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DiscoveryService::class)]
#[CoversClass(Pacer::class)]
final class DiscoveryTimingTest extends TestCase
{
    use UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var int The least time a discovery start takes in the comparisons, in milliseconds. */
    private const int FLOOR = 100;

    /** @var int How many matches, and how many misses, each comparison runs. */
    private const int RUNS = 15;

    /** @var int The most the two groups' medians may differ by, in nanoseconds. */
    private const int MAX_MEDIAN_DIFFERENCE = 15000000;

    /** @var int Nanoseconds in a millisecond. */
    private const int NANOSECONDS_PER_MILLISECOND = 1000000;

    /** @var \Tests\Fixtures\Protocols\StartingDriver The driver the connection runs over. */
    private StartingDriver $driver;

    /**
     * Bind a fixed clock and a request, turn discovery on with a 100 ms floor
     * and limits no comparison reaches, register the application and the
     * driver, create the tables, a usable connection and its verified domain.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->driver = new StartingDriver;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance('request', Request::create('/auth/sso/discovery', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.oidc', true);
        config()->set('sso.features.discovery', true);
        config()->set('sso.discovery.minimum_duration_milliseconds', self::FLOOR);
        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 1000, 'decay_seconds' => 60]);
        config()->set('sso.applications', [
            'discovering' => [
                'redirect_uri'     => 'https://app.example.com/sso',
                'external_sign_in' => true,
                'discovery'        => ['enabled' => true, 'fallback_url' => 'https://app.example.com/sign-in'],
            ],
        ]);

        $driver = $this->driver;

        app(ProtocolManager::class)->extend(StartingDriver::NAME, fn (): StartingDriver => $driver);

        $this->createConnectionTables();
        $this->createDomainsTable();
        $this->createFlowTables();
        self::rateLimitsMigration()->up(); // @phpstan-ignore method.notFound

        $connection = $this->makeConnection([
            'protocol' => StartingDriver::NAME,
            'enabled'  => true,
            'settings' => ['issuer' => 'https://idp.example.com'],
        ]);

        $this->makeDomain($connection, 'example.com', ['state' => DomainState::VERIFIED]);
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::rateLimitsMigration()->down(); // @phpstan-ignore method.notFound
        $this->dropFlowTables();
        $this->dropDomainsTable();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * Matches and misses, interleaved, each take at least the floor, and their
     * medians differ by less than 15 ms.
     *
     * @return void
     */
    public function testAMatchAndAMissTakeTheSameTime(): void
    {
        $this->assertTheSameTime(fn (): null => null);

        self::assertSame(self::RUNS, AuthorizationRequest::query()->count());
    }

    /**
     * A driver that takes 30 ms to start keeps the property: the match's extra
     * work is within the floor, which the miss waits out too.
     *
     * @return void
     */
    public function testASlowDriverKeepsTheSameTime(): void
    {
        $driver = $this->driver;

        $this->assertTheSameTime(static function () use ($driver): void {
            $driver->onStart = static function (): void {
                usleep(30000);
            };
        });

        self::assertCount(self::RUNS, $this->driver->starts());
    }

    /**
     * The pacer waits until the floor has passed since the answer started, and
     * no longer once it has: what remains is the whole floor at the start, less
     * as time passes, and none, never fewer, once the floor is past.
     *
     * @return void
     */
    public function testThePacerWaitsOutTheRestOfTheFloorAndNeverLess(): void
    {
        config()->set('sso.discovery.minimum_duration_milliseconds', 2000);

        $pacer = app(Pacer::class);

        $startedAt = $pacer->start();
        $remaining = $pacer->remaining($startedAt);

        self::assertLessThanOrEqual(2000000, $remaining);
        self::assertGreaterThan(1000000, $remaining);
        self::assertSame(0, $pacer->remaining($startedAt - 2000 * self::NANOSECONDS_PER_MILLISECOND));
        self::assertSame(0, $pacer->remaining($startedAt - 60000 * self::NANOSECONDS_PER_MILLISECOND));

        $before = (int) hrtime(true);

        $pacer->finish($startedAt - 60000 * self::NANOSECONDS_PER_MILLISECOND);

        self::assertLessThan(1000 * self::NANOSECONDS_PER_MILLISECOND, (int) hrtime(true) - $before);

        config()->set('sso.discovery.minimum_duration_milliseconds', 50);

        $startedAt = $pacer->start();

        $pacer->finish($startedAt);

        self::assertGreaterThanOrEqual(50 * self::NANOSECONDS_PER_MILLISECOND, (int) hrtime(true) - $startedAt);
        self::assertSame(0, $pacer->remaining($startedAt));
    }

    /**
     * An exception is not held: a misbound start throws at once, whatever the
     * floor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExceptionIsNotHeld(): void
    {
        config()->set('sso.discovery.minimum_duration_milliseconds', 2000);

        $startedAt = (int) hrtime(true);

        try {
            $this->service()->start('discovering', Purpose::LINK, 'someone@example.com');
            self::fail('A misbound start was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A `link` flow is started for an identity, with no session.', $exception->getMessage());
        }

        self::assertLessThan(1000 * self::NANOSECONDS_PER_MILLISECOND, (int) hrtime(true) - $startedAt);
    }

    /**
     * A floor below 50 ms fails closed before anything is counted, read or
     * stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFloorBelowTheLeastFailsClosedBeforeAnythingIsCounted(): void
    {
        config()->set('sso.discovery.minimum_duration_milliseconds', 49);

        try {
            $this->service()->start('discovering', Purpose::SIGN_IN, 'someone@example.com');
            self::fail('A floor below 50 ms was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('sso.discovery.minimum_duration_milliseconds must be an integer from 50 to 2000.', $exception->getMessage());
        }

        self::assertSame(0, DB::table(StorageConnection::table('rate_limits.table'))->count());
        self::assertSame([], $this->driver->starts());
        self::assertSame(0, AuthorizationRequest::query()->count());
    }

    /**
     * A floor below 50 ms is refused at boot by `[flows]`, with the key and its
     * range, as the application boots to serve a request.
     *
     * @return void
     */
    public function testAFloorBelowTheLeastIsRefusedAtBoot(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $app->bind(ConfigurationChecker::class, static fn (Application $app): ConfigurationChecker => new ConfigurationChecker($app, ['flows' => FlowsCheck::class]));

        (new \ReflectionProperty(Application::class, 'isRunningInConsole'))->setValue($app, false);

        config()->set('sso.discovery.minimum_duration_milliseconds', 49);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage(
            "laravel-sso is misconfigured; `php artisan sso:check` lists the same problems:\n"
            . '- [flows] sso.discovery.minimum_duration_milliseconds must be an integer from 50 to 2000.',
        );

        (new SsoServiceProvider($app))->boot();
    }

    /**
     * Run the matches and the misses, interleaved, each match after the
     * preparation given, and assert each took at least the floor and the
     * medians differ by less than the most allowed.
     *
     * @param  \Closure(): mixed  $beforeMatch
     * @return void
     */
    private function assertTheSameTime(\Closure $beforeMatch): void
    {
        $matches = [];
        $misses  = [];

        for ($run = 0; $run < self::RUNS; $run++) {

            $beforeMatch();

            [$match, $matches[]] = $this->timed('someone@example.com');
            [$miss, $misses[]]   = $this->timed('someone@unknown.com');

            self::assertSame(['https://idp.example.com', 'https://app.example.com'], [self::origin($match), self::origin($miss)]);
        }

        foreach ([...$matches, ...$misses] as $took) {
            self::assertGreaterThanOrEqual(self::FLOOR * self::NANOSECONDS_PER_MILLISECOND, $took);
        }

        $difference = abs(self::median($matches) - self::median($misses));

        self::assertLessThan(self::MAX_MEDIAN_DIFFERENCE, $difference, sprintf('The medians differ by %.2f ms.', $difference / self::NANOSECONDS_PER_MILLISECOND));
    }

    /**
     * Start a `sign_in` for `discovering` by the email, and answer the result
     * with the nanoseconds it took.
     *
     * @param  string  $email
     * @return array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: int}
     */
    private function timed(string $email): array
    {
        $startedAt = (int) hrtime(true);
        $result    = $this->service()->start('discovering', Purpose::SIGN_IN, $email);
        $took      = (int) hrtime(true) - $startedAt;

        self::assertTrue($result->isStarted());

        return [$result, $took];
    }

    /**
     * The scheme and host the result's navigation leads to.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $result
     * @return string
     */
    private static function origin(StartResult $result): string
    {
        $url = (string) $result->navigation?->jsonSerialize()['url'];

        return implode('/', array_slice(explode('/', $url), 0, 3));
    }

    /**
     * The median of an odd number of durations.
     *
     * @param  list<int>  $durations
     * @return int
     */
    private static function median(array $durations): int
    {
        sort($durations);

        return $durations[intdiv(count($durations), 2)];
    }

    /**
     * The service, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Discovery\DiscoveryService
     */
    private function service(): DiscoveryService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DiscoveryService::class);
    }

    /**
     * The shipped migration of the rate limit counters.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function rateLimitsMigration(): Migration
    {
        return require dirname(__DIR__, 3) . self::RATE_LIMITS_MIGRATION;
    }
}
