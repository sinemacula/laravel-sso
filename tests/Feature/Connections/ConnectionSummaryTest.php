<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Connections\ConnectionSummary;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Secrets\MaskedSecret;
use SineMacula\Laravel\Sso\Secrets\Secret;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Protocols\ExampleDriver;
use Tests\TestCase;

/**
 * Feature tests for the connection summary the helpers return.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionSummary::class)]
final class ConnectionSummaryTest extends TestCase
{
    use UsesConnections;

    /** @var string A client secret no output may show. */
    private const string SECRET = 'the-client-secret-value';

    /**
     * Bind a fixed clock, create the tables, and register the example protocol.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        $this->usePackageTables();

        $this->protocols()->extend('example', fn (): ExampleDriver => new ExampleDriver);
    }

    /**
     * Every field is the connection's, with the declared secrets masked.
     *
     * @return void
     */
    public function testSummarizesTheConnection(): void
    {
        $connection = $this->makeConnection([
            'settings'          => ['issuer' => 'https://idp.example.com'],
            'secrets'           => $this->secrets()->apply(null, ['client_secret' => new Secret(self::SECRET)]),
            'attribute_mapping' => ['email' => 'email'],
        ]);

        $summary = $this->summaryOf($connection);

        self::assertSame($connection->id, $summary->id);
        self::assertSame('tenant-1', $summary->tenantId);
        self::assertSame('oidc', $summary->protocol);
        self::assertSame('Example', $summary->displayName);
        self::assertSame(['issuer' => 'https://idp.example.com'], $summary->settings);
        self::assertEquals(['client_secret' => MaskedSecret::set()], $summary->secrets);
        self::assertSame(['email' => 'email'], $summary->attributeMapping);
        self::assertFalse($summary->enabled);
        self::assertFalse($summary->hasCompletedSignIn);
        self::assertFalse($summary->usable);
        self::assertInstanceOf(CarbonImmutable::class, $summary->createdAt);
        self::assertSame('2026-11-01T09:30:00+00:00', $summary->createdAt->toIso8601String());
        self::assertSame('2026-11-01T09:30:00+00:00', $summary->updatedAt->toIso8601String());
    }

    /**
     * An unset secret is masked as unset; SAML and unregistered protocols
     * declare none.
     *
     * @return void
     */
    public function testMasksEachDeclaredSecret(): void
    {
        self::assertEquals(['client_secret' => MaskedSecret::unset()], $this->summaryOf($this->makeConnection())->secrets);
        self::assertSame([], $this->summaryOf($this->makeConnection(['protocol' => 'saml2']))->secrets);
        self::assertSame([], $this->summaryOf($this->makeConnection(['protocol' => 'retired']))->secrets);
        self::assertEquals(['api_secret' => MaskedSecret::unset()], $this->summaryOf($this->makeConnection(['protocol' => 'example']))->secrets);
    }

    /**
     * Usable only while enabled, its protocol available and its settings
     * complete.
     *
     * @return void
     */
    public function testIsUsableAsTheProtocolsJudgeIt(): void
    {
        $complete = $this->makeConnection(['protocol' => 'example', 'settings' => ['issuer' => 'https://idp.example.com'], 'enabled' => true]);

        self::assertFalse($this->summaryOf($complete)->usable);

        config()->set('sso.features.oidc', true);

        self::assertTrue($this->summaryOf($complete)->usable);
        self::assertFalse($this->summaryOf($this->makeConnection(['protocol' => 'example', 'enabled' => true]))->usable);
        self::assertFalse($this->summaryOf($this->makeConnection(['protocol' => 'example', 'settings' => ['issuer' => 'https://idp.example.com']]))->usable);
        self::assertFalse($this->summaryOf($this->makeConnection(['protocol' => 'retired', 'enabled' => true]))->usable);
        self::assertFalse($this->summaryOf($this->makeConnection(['enabled' => true]))->usable);
    }

    /**
     * The JSON uses snake_case and UTC, maps empty objects, and holds no secret
     * or ciphertext.
     *
     * @return void
     */
    public function testSerializesWithoutASecretOrCiphertext(): void
    {
        $secrets    = $this->secrets()->apply(null, ['client_secret' => new Secret(self::SECRET)]);
        $connection = $this->makeConnection(['secrets' => $secrets, 'has_completed_sign_in' => true]);

        $json = (string) json_encode($this->summaryOf($connection));

        self::assertSame(sprintf(
            '{"id":"%s","tenant_id":"tenant-1","protocol":"oidc","display_name":"Example","settings":{},'
            . '"secrets":{"client_secret":{"set":true}},"attribute_mapping":{},"enabled":false,"has_completed_sign_in":true,'
            . '"usable":false,"created_at":"2026-11-01T09:30:00Z","updated_at":"2026-11-01T09:30:00Z"}',
            $connection->id,
        ), $json);

        self::assertSame(['client_secret' => ['set' => true]], $this->summaryOf($connection)->jsonSerialize()['secrets']);
        self::assertIsString($secrets);
        self::assertStringNotContainsString(self::SECRET, $json);

        foreach ((array) json_decode($secrets, true) as $ciphertext) {
            self::assertIsString($ciphertext);
            self::assertStringNotContainsString($ciphertext, $json);
        }
    }

    /**
     * The summary of the connection as stored.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionSummary
     */
    private function summaryOf(Connection $connection): ConnectionSummary
    {
        $stored = Connection::query()->findOrFail($connection->id);

        return ConnectionSummary::of($stored, $this->protocols(), $this->secrets());
    }

    /**
     * The protocol registry.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\ProtocolManager
     */
    private function protocols(): ProtocolManager
    {
        $protocols = $this->app?->make(ProtocolManager::class);

        self::assertInstanceOf(ProtocolManager::class, $protocols);

        return $protocols;
    }

    /**
     * The connections' secrets.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionSecrets
     */
    private function secrets(): ConnectionSecrets
    {
        $secrets = $this->app?->make(ConnectionSecrets::class);

        self::assertInstanceOf(ConnectionSecrets::class, $secrets);

        return $secrets;
    }
}
