<?php

declare(strict_types = 1);

namespace Tests\Integration\Connections;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Secrets\Secret;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Protocols\ExampleDriver;
use Tests\TestCase;

/**
 * Integration tests of a stored connection and its driver, on whichever engine
 * the suite runs against: a connection read back from the write connection is
 * usable only while it is enabled, its protocol available and its settings
 * complete (SSO-2.1), and a connection over a package protocol is never usable
 * until that protocol's flows land, however it is configured.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProtocolManager::class)]
#[CoversClass(Connection::class)]
final class ConnectionUsabilityTest extends TestCase
{
    use UsesConnections;

    /**
     * Create the tables, turn OIDC on and register the example driver.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.features.oidc', true);

        $this->createConnectionTables();

        app(ProtocolManager::class)->extend('example', fn (): ProtocolDriver => new ExampleDriver);
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A stored connection, read back from the write connection, is usable once
     * enabled with complete settings, and not once disabled or incomplete; its
     * driver starts a flow with what it stored.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAStoredConnectionIsUsableOnlyWhileEnabledAndComplete(): void
    {
        $manager = app(ProtocolManager::class);
        $stored  = $this->makeConnection(['protocol' => 'example', 'settings' => ['issuer' => 'https://idp.example.com']]);

        self::assertFalse($manager->isUsable($this->read($stored)));

        $stored->forceFill(['enabled' => true])->save();

        $read = $this->read($stored);

        self::assertTrue($manager->isUsable($read));

        $start = $manager->protocol($read->getProtocol())->start($read, new StartRequest(Purpose::SIGN_IN, 'web', RequestReference::generate(), new Secret('state')));

        self::assertSame('https://idp.example.com', $start->navigation?->url());

        $stored->forceFill(['settings' => []])->save();

        self::assertFalse($manager->isUsable($this->read($stored)));

        $stored->forceFill(['settings' => ['issuer' => 'https://idp.example.com'], 'enabled' => false])->save();

        self::assertFalse($manager->isUsable($this->read($stored)));
    }

    /**
     * A connection over a package protocol is never usable before that
     * protocol's flows land, and its driver refuses to start.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAPackageProtocolIsNeverUsableYet(): void
    {
        $manager = app(ProtocolManager::class);
        $stored  = $this->makeConnection(['protocol' => 'oidc', 'enabled' => true, 'settings' => ['issuer' => 'https://idp.example.com']]);
        $read    = $this->read($stored);

        $start = $manager->protocol('oidc')->start($read, new StartRequest(Purpose::SIGN_IN, 'web', RequestReference::generate(), new Secret('state')));

        self::assertFalse($manager->isUsable($read));
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $start->reason);
    }

    /**
     * The connection as the write connection holds it now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function read(Connection $connection): Connection
    {
        return Connection::query()->useWritePdo()->findOrFail($connection->id);
    }
}
