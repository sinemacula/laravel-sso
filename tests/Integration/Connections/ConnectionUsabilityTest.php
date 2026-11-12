<?php

declare(strict_types = 1);

namespace Tests\Integration\Connections;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
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
 * Integration tests for whether a stored connection is usable.
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
     * Create the tables, enable OIDC, configure the endpoints and register the
     * example driver.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://api.example.com');

        $this->usePackageTables();

        app(ProtocolManager::class)->extend('example', fn (): ProtocolDriver => new ExampleDriver);
    }

    /**
     * A stored connection is usable only while enabled and complete, and its
     * driver starts a flow.
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
     * An OIDC connection with incomplete settings is not usable, even when
     * enabled.
     *
     * @return void
     */
    public function testAnOidcConnectionWithIncompleteSettingsIsNotUsable(): void
    {
        $stored = $this->makeConnection(['protocol' => 'oidc', 'enabled' => true, 'settings' => ['issuer' => 'https://idp.example.com']]);

        self::assertFalse(app(ProtocolManager::class)->isUsable($this->read($stored)));
    }

    /**
     * An OIDC connection is usable once it has its client secret, and starts a
     * flow to its endpoint.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACompleteOidcConnectionIsUsableAndStarts(): void
    {
        $manager = app(ProtocolManager::class);
        $stored  = $this->makeConnection(['protocol' => 'oidc', 'enabled' => true, 'settings' => [
            'issuer'                 => 'https://idp.example.com',
            'authorization_endpoint' => 'https://idp.example.com/authorize',
            'token_endpoint'         => 'https://idp.example.com/token',
            'jwks_uri'               => 'https://idp.example.com/jwks',
            'client_id'              => 'client-1',
        ]]);

        self::assertFalse($manager->isUsable($this->read($stored)));

        $stored->forceFill(['secrets' => app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret('the-client-secret')])])->save();

        $read = $this->read($stored);

        self::assertTrue($manager->isUsable($read));

        $request = new StartRequest(Purpose::SIGN_IN, 'web', RequestReference::generate(), new Secret('state'), new Secret('nonce'), new Secret('verifier'));
        $start   = $manager->protocol($read->getProtocol())->start($read, $request);

        self::assertSame(['https://idp.example.com', false, null], [$start->expectedIssuer, $start->issuerRequired, $start->reason]);
        self::assertStringStartsWith('https://idp.example.com/authorize?response_type=code&client_id=client-1&', (string) $start->navigation?->url());
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
