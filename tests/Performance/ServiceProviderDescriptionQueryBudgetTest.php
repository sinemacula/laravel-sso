<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\UsesConnections;

/**
 * Query budgets for the public JWKS, a body an unauthenticated route serves for
 * a connection named in its URL, so its reads must not grow with what a
 * connection holds or depend on who asks (SSO-2.7):
 *
 * - an id that names no connection, empty or longer than a ULID: nothing;
 * - an unknown id: 1 read, the connection;
 * - a protocol with no such keys, a protocol switched off, a client secret
 *   method or an unsupported one: 1 read, the connection;
 * - `private_key_jwt`: 2 reads, the connection and its key ring together,
 *   whether it holds no key, one or a current and a next.
 *
 * None of them writes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ServiceProviderDescriptions::class)]
final class ServiceProviderDescriptionQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections;

    /** @var string The tenant the connections belong to. */
    private const string TENANT = 'tenant-1';

    /**
     * Turn OIDC on, name the endpoints and bind a fresh freshness contract.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
    }

    /**
     * An id that names no connection is not looked up.
     *
     * @return void
     */
    public function testAnIdThatNamesNothingSendsNothing(): void
    {
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->publicKeysOf('', 0)->reason);
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->publicKeysOf(str_repeat('a', 27), 0)->reason);
    }

    /**
     * An unknown id is one read.
     *
     * @return void
     */
    public function testAnUnknownIdIsOneRead(): void
    {
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->publicKeysOf('01jbunknownconnection00000', 1)->reason);
    }

    /**
     * A client secret method, an unsupported one, a protocol with no such keys
     * and a protocol switched off are each the read of the connection alone.
     *
     * @return void
     */
    public function testARefusalBeforeTheKeysIsOneRead(): void
    {
        $secret      = $this->oidc('client_secret_basic');
        $unsupported = $this->oidc('tls_client_auth');
        $saml        = $this->makeConnection(['tenant_id' => self::TENANT, 'protocol' => 'saml2']);
        $off         = $this->oidc('private_key_jwt');

        config()->set('sso.features.saml2', true);

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->publicKeysOf($secret->id, 1)->reason);
        self::assertSame(FailureReason::SETTINGS_INVALID, $this->publicKeysOf($unsupported->id, 1)->reason);
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->publicKeysOf($saml->id, 1)->reason);

        config()->set('sso.features.oidc', false);

        self::assertSame(FailureReason::PROTOCOL_UNAVAILABLE, $this->publicKeysOf($off->id, 1)->reason);
    }

    /**
     * `private_key_jwt` is two reads with no key, one, or a current and a next.
     *
     * @return void
     */
    public function testThePublicKeysAreTwoReadsHoweverManyKeys(): void
    {
        $connection = $this->oidc('private_key_jwt');

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->publicKeysOf($connection->id, 2)->reason);

        $this->addKey($connection);

        self::assertTrue($this->publicKeysOf($connection->id, 2)->isAvailable());

        $this->addKey($connection);

        self::assertTrue($this->publicKeysOf($connection->id, 2)->isAvailable());
    }

    /**
     * The public keys of the id given, asserted to cost the reads given and no
     * write.
     *
     * @param  string  $id
     * @param  int  $reads
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     */
    private function publicKeysOf(string $id, int $reads): ServiceProviderDescription
    {
        return $this->assertQueryBudget($reads, 0, fn (): ServiceProviderDescription => $this->descriptions()->publicKeys($id));
    }

    /**
     * An OIDC connection of the tenant using the method.
     *
     * @param  string  $method
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function oidc(string $method): Connection
    {
        return $this->makeConnection([
            'tenant_id' => self::TENANT,
            'secrets'   => app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret('the-client-secret-value')]),
            'settings'  => ['issuer' => 'https://idp.example.test', 'client_authentication' => $method, 'client_id' => 'client-123'],
        ]);
    }

    /**
     * Add a client assertion key to the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     */
    private function addKey(Connection $connection): void
    {
        self::assertTrue(app(KeyService::class)->addNext(self::TENANT, $connection->id, KeyUse::CLIENT_ASSERTION, KeyType::EC)->isSucceeded());
    }

    /**
     * The helper, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions
     */
    private function descriptions(): ServiceProviderDescriptions
    {
        return app(ServiceProviderDescriptions::class);
    }
}
