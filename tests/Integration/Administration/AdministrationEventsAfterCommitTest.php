<?php

declare(strict_types = 1);

namespace Tests\Integration\Administration;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\ConnectionCreated;
use SineMacula\Laravel\Sso\Events\ConnectionEnabled;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\KeyAdded;
use SineMacula\Laravel\Sso\Events\KeyMadeCurrent;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RecordsEventSequences;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Integration tests, on SQLite, of when the administration events reach their
 * listeners (SSO-10.5), with the storage connection moved to a connection of
 * its own beside the suite's database: a management helper run inside an outer
 * transaction on the storage connection that rolls back writes nothing and
 * reports nothing; one that commits reports only once the outer transaction
 * commits; a transaction on another connection defers nothing; and a queued
 * listener receives a connection update with its names and context intact.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdministrationEvents::class)]
#[CoversClass(ConnectionService::class)]
#[CoversClass(KeyService::class)]
final class AdministrationEventsAfterCommitTest extends TestCase
{
    use RecordsEventSequences;

    /** @var string The connection the package's tables are moved to. */
    private const string STORE = 'sso_administration_store';

    /** @var string The tenant whose connection the helpers act on. */
    private const string TENANT = 'tenant-1';

    /** @var array<string, string> The settings of a complete OIDC connection. */
    private const array OIDC = [
        'issuer'                 => 'https://idp.example.com',
        'authorization_endpoint' => 'https://idp.example.com/authorize',
        'token_endpoint'         => 'https://idp.example.com/token',
        'jwks_uri'               => 'https://idp.example.com/jwks',
        'client_id'              => 'client-123',
        'client_secret'          => 'the-client-secret-value',
    ];

    /** @var \SineMacula\Laravel\Sso\Administration\ActingIdentity Who makes each change. */
    private ActingIdentity $actor;

    /** @var string The OIDC connection the helpers act on. */
    private string $connection;

    /**
     * Bind a fixed clock and a freshness contract that answers `fresh`, turn
     * OIDC on, create the tables on the storage connection and an OIDC
     * connection, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->actor = new ActingIdentity('App\Models\User', '42');

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00.250000Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        config()->set('sso.features.oidc', true);

        $this->usePackageTables();

        $this->connection = (string) $this->connections()->create(self::TENANT, 'oidc', 'Acme', Clients::browser(), self::OIDC, actor: $this->actor)->connection?->id;

        $this->startRecordingEvents();
    }

    /**
     * Helpers run inside an outer transaction on the storage connection that
     * rolls back write nothing and report nothing, though each succeeded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOperationRolledBackWritesAndReportsNothing(): void
    {
        $before = $this->connectionRow();

        try {
            DB::connection(self::STORE)->transaction(function (): void {

                self::assertTrue($this->connections()->create(self::TENANT, 'oidc', 'Second', Clients::browser(), self::OIDC, actor: $this->actor)->isSucceeded());
                self::assertTrue($this->connections()->update(
                    self::TENANT,
                    $this->connection,
                    ['settings' => ['token_endpoint' => 'https://idp.example.com/oauth/token']],
                    Clients::browser(),
                    $this->actor,
                )->isSucceeded());
                self::assertTrue($this->connections()->enable(self::TENANT, $this->connection, Clients::browser(), $this->actor)->isSucceeded());
                self::assertTrue($this->keys()->addNext(self::TENANT, $this->connection, KeyUse::CLIENT_ASSERTION, Clients::browser(), KeyType::EC, $this->actor)->isSucceeded());

                $this->assertNoEvents();

                throw new \RuntimeException('Rolled back.');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('Rolled back.', $exception->getMessage());
        }

        self::assertSame(1, Connection::query()->count());
        self::assertSame(0, ConnectionKey::query()->count());
        self::assertSame($before, $this->connectionRow());
        $this->assertNoEvents();
    }

    /**
     * Helpers run inside an outer transaction on the storage connection that
     * commits report nothing until it commits, then each change in order.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOperationCommittedReportsOnlyAfterTheCommit(): void
    {
        DB::connection(self::STORE)->transaction(function (): void {

            $this->connections()->update(
                self::TENANT,
                $this->connection,
                ['settings' => ['token_endpoint' => 'https://idp.example.com/oauth/token']],
                Clients::browser(),
                $this->actor,
            );
            $this->connections()->enable(self::TENANT, $this->connection, Clients::browser(), $this->actor);
            $this->keys()->addNext(self::TENANT, $this->connection, KeyUse::CLIENT_ASSERTION, Clients::browser(), KeyType::EC, $this->actor);

            $this->assertNoEvents();
        });

        $this->assertEventSequence([ConnectionUpdated::class, ConnectionEnabled::class, KeyAdded::class, KeyMadeCurrent::class]);

        self::assertSame(1, ConnectionKey::query()->count());
        self::assertTrue(Connection::query()->findOrFail($this->connection)->enabled);
    }

    /**
     * A transaction open on the suite's own database, which the package does
     * not write to, neither defers the event nor withdraws it when it rolls
     * back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransactionOnAnotherConnectionDefersNothing(): void
    {
        DB::connection()->beginTransaction();

        $this->connections()->create(self::TENANT, 'oidc', 'Second', Clients::browser(), self::OIDC, actor: $this->actor);

        $this->assertEventSequence([ConnectionCreated::class]);

        DB::connection()->rollBack();

        $this->assertEventSequence([ConnectionCreated::class]);

        self::assertSame(2, Connection::query()->count());
    }

    /**
     * A queued listener, on the `sync` queue, which serialises the event as any
     * queue does, receives the connection update once the outer transaction
     * commits, with the names of what changed and its context intact.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAQueuedListenerReceivesTheUpdateIntact(): void
    {
        config()->set('queue.default', 'sync');

        $listener = new class implements ShouldQueue {
            /** @var list<\SineMacula\Laravel\Sso\Events\ConnectionUpdated> The events received, in order. */
            private static array $received = [];

            /**
             * Forget the events received.
             *
             * @return void
             */
            public static function forget(): void
            {
                self::$received = [];
            }

            /**
             * The events received, in order.
             *
             * @return list<\SineMacula\Laravel\Sso\Events\ConnectionUpdated>
             */
            public static function received(): array
            {
                return self::$received;
            }

            /**
             * Record the event as the queue hands it back.
             *
             * @param  \SineMacula\Laravel\Sso\Events\ConnectionUpdated  $event
             * @return void
             */
            public function handle(ConnectionUpdated $event): void
            {
                self::$received[] = $event;
            }
        };

        $listener::forget();

        Event::listen(ConnectionUpdated::class, [$listener::class, 'handle']);

        $this->app?->instance('request', Request::create('/', 'POST', [], [], [], [
            'REMOTE_ADDR'     => '203.0.113.7',
            'HTTP_USER_AGENT' => 'Example/1.0',
        ]));

        DB::connection(self::STORE)->transaction(function () use ($listener): void {

            $this->connections()->update(
                self::TENANT,
                $this->connection,
                ['display_name' => 'Renamed', 'settings' => ['client_secret' => 'the-rotated-client-secret']],
                Clients::browser(),
                $this->actor,
            );

            self::assertSame([], $listener::received());
        });

        self::assertCount(1, $listener::received());

        $this->assertEventSequence([ConnectionUpdated::class]);

        $sent     = $this->recordedEvents()[0];
        $received = $listener::received()[0];

        self::assertInstanceOf(ConnectionUpdated::class, $sent);
        self::assertNotSame($sent, $received);
        self::assertSame(['client_secret', 'display_name'], $received->changedSettings);
        self::assertSame($sent->context()->toArray(), $received->context()->toArray());
        self::assertSame([
            'occurred_at'                 => '2026-11-01T09:30:00.250000Z',
            'ip'                          => '203.0.113.7',
            'user_agent'                  => 'Example/1.0',
            'connection_id'               => $this->connection,
            'connection_tenant_id'        => self::TENANT,
            'protocol'                    => 'oidc',
            'application'                 => null,
            'purpose'                     => null,
            'request_reference'           => null,
            'identity_morph_class'        => null,
            'identity_id'                 => null,
            'acting_identity_morph_class' => 'App\Models\User',
            'acting_identity_id'          => '42',
            'principal_morph_class'       => null,
            'principal_id'                => null,
            'tenant_id'                   => null,
            'session_id'                  => null,
            'method'                      => null,
        ], $received->context()->toArray());
    }

    /**
     * Add the second connection, and move the storage connection to it.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('database.connections.' . self::STORE, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        config()->set('sso.storage.connection', self::STORE);
    }

    /**
     * The OIDC connection's row, as stored.
     *
     * @return array<string, mixed>
     */
    private function connectionRow(): array
    {
        $row = DB::connection(self::STORE)->table(StorageConnection::table('connections.table'))->where('id', $this->connection)->first();

        self::assertIsObject($row);

        return (array) $row;
    }

    /**
     * The connection helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionService
     */
    private function connections(): ConnectionService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ConnectionService::class);
    }

    /**
     * The key helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Keys\KeyService
     */
    private function keys(): KeyService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(KeyService::class);
    }
}
