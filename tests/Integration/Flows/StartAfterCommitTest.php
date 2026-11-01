<?php

declare(strict_types = 1);

namespace Tests\Integration\Flows;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestEvents;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Protocols\StartingDriver;
use Tests\TestCase;

/**
 * How a start meets transactions (SSO-10.5, SSO-11.5), on every database the
 * suite runs on: `AuthorizationRequestStarted` reaches its listeners only once
 * the transaction that stored the request commits; and a start called inside
 * the caller's transaction on the storage connection, which would keep the
 * connection's lock while the driver may reach the identity provider, is a
 * `LogicException` before it counts, asks, stores or reports anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequestService::class)]
#[CoversClass(RequestEvents::class)]
final class StartAfterCommitTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection. */
    private Connection $connection;

    /** @var \Tests\Fixtures\Protocols\StartingDriver The driver the connection runs over. */
    private StartingDriver $driver;

    /**
     * Bind a fixed clock, register the application and the driver, create the
     * tables and a usable connection, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', [
            'web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
        ]);

        $this->driver = new StartingDriver;
        $driver       = $this->driver;

        app(ProtocolManager::class)->extend(StartingDriver::NAME, fn (): StartingDriver => $driver);

        $this->createConnectionTables();
        $this->createFlowTables();
        self::rateLimitsMigration()->up(); // @phpstan-ignore method.notFound

        $this->connection = $this->makeConnection([
            'protocol' => StartingDriver::NAME,
            'enabled'  => true,
            'settings' => ['issuer' => 'https://idp.example.com'],
        ]);

        $this->startRecordingEvents();
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
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A start reports `AuthorizationRequestStarted` only once the transaction
     * that stored its request commits, and a refusal reports its failure
     * outside any transaction.
     *
     * @return void
     */
    public function testAStartIsReportedOnceItsRequestIsCommitted(): void
    {
        $levels = [];

        Event::listen(SsoEvent::class, static function () use (&$levels): void {
            $levels[] = DB::connection(StorageConnection::name())->transactionLevel();
        });

        self::assertTrue($this->startFlow()->isStarted());
        self::assertTrue($this->startFlow('missing')->isRefused());

        self::assertSame([0, 0], $levels);
        self::assertSame(1, AuthorizationRequest::query()->count());
        $this->assertEventSequence([AuthorizationRequestStarted::class, FlowFailed::class]);
    }

    /**
     * Each application a start inside a transaction names: one that would
     * start, and one that would be refused.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function applications(): iterable
    {
        yield 'started' => ['web'];
        yield 'refused' => ['missing'];
    }

    /**
     * A start called inside the caller's transaction on the storage connection
     * is refused before anything else, whether it would start or be refused: no
     * attempt counted, no driver asked, no request stored and nothing reported.
     * Once the caller's transaction is over, it starts.
     *
     * @param  string  $application
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('applications')]
    public function testAStartInsideATransactionIsRefusedBeforeAnythingElse(string $application): void
    {
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        try {
            $this->startFlow($application);

            self::fail('A start inside the caller\'s transaction was answered.');
        } catch (\LogicException $exception) {
            self::assertSame(
                'A start runs outside any transaction on the package\'s storage connection: it calls the protocol driver.',
                $exception->getMessage(),
            );
        } finally {
            $database->rollBack();
        }

        self::assertSame([], $this->driver->starts());
        self::assertSame(0, AuthorizationRequest::query()->count());
        self::assertSame(0, DB::table(StorageConnection::table('rate_limits.table'))->count());
        $this->assertNoEvents();

        self::assertTrue($this->startFlow()->isStarted());
        $this->assertEventSequence([AuthorizationRequestStarted::class]);
    }

    /**
     * Start a `sign_in` for the application through the usable connection.
     *
     * @param  string  $application
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \LogicException
     */
    private function startFlow(string $application = 'web'): StartResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(AuthorizationRequestService::class)->start($application, Purpose::SIGN_IN, $this->connection->id);
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
