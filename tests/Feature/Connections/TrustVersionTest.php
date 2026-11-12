<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Models\Connection;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\TestCase;

/**
 * Feature tests for a connection's trust version.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InFlightVoider::class)]
#[CoversClass(ConnectionService::class)]
#[CoversClass(ConnectionLifecycle::class)]
final class TrustVersionTest extends TestCase
{
    use UsesConnections;

    /** @var string The tenant. */
    private const string TENANT = 'tenant-1';

    /**
     * Bind a fixed clock and a fresh caller, and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, new RecordingFreshness);

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.oidc', true);

        $this->usePackageTables();
    }

    /**
     * Each voiding raises the trust version by one, in the row and in memory.
     *
     * @return void
     */
    public function testVoidingRaisesTheTrustVersionByOne(): void
    {
        $connection = $this->makeConnection();
        $other      = $this->makeConnection();

        DB::connection(StorageConnection::name())->transaction(static function () use ($connection): void {
            app(InFlightVoider::class)->voidFor($connection);
            app(InFlightVoider::class)->voidFor($connection);
        });

        self::assertSame(2, $connection->trust_version);
        self::assertSame([2, 0], [self::trustVersion($connection), self::trustVersion($other)]);
    }

    /**
     * A trust change of the settings raises it; one asking no trust leaves it.
     *
     * @return void
     */
    public function testATrustChangeOfTheSettingsRaisesIt(): void
    {
        $created    = $this->connections()->create(self::TENANT, 'saml2', 'Example', Clients::browser(), ['sso_url' => 'https://idp.example.com/sso']);
        $connection = Connection::query()->whereKey((string) $created->connection?->id)->sole();

        $this->connections()->update(self::TENANT, $connection->id, ['settings' => ['force_authn' => true]], Clients::browser());

        self::assertSame(0, self::trustVersion($connection));

        $this->connections()->update(self::TENANT, $connection->id, ['settings' => ['sso_url' => 'https://idp.example.com/login']], Clients::browser());

        self::assertSame(1, self::trustVersion($connection));
    }

    /**
     * Disabling and enabling raise it; repeating either leaves it.
     *
     * @return void
     */
    public function testDisablingAndEnablingRaiseIt(): void
    {
        $connection = $this->makeConnection();

        self::assertTrue($this->connections()->enable(self::TENANT, $connection->id, Clients::browser())->isSucceeded());
        self::assertSame(1, self::trustVersion($connection));

        $this->connections()->enable(self::TENANT, $connection->id, Clients::browser());
        self::assertSame(1, self::trustVersion($connection));

        self::assertTrue(app(ConnectionLifecycle::class)->disable(self::TENANT, $connection->id, Clients::browser())->isSucceeded());
        self::assertSame(2, self::trustVersion($connection));

        app(ConnectionLifecycle::class)->disable(self::TENANT, $connection->id, Clients::browser());
        self::assertSame(2, self::trustVersion($connection));
    }

    /**
     * The management helpers.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionService
     */
    private function connections(): ConnectionService
    {
        return app(ConnectionService::class);
    }

    /**
     * The connection's trust version as stored.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return int
     */
    private static function trustVersion(Connection $connection): int
    {
        return Connection::query()->findOrFail($connection->id)->trust_version;
    }
}
