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
use SineMacula\Laravel\Sso\Protocols\Oidc\RelyingPartyDescription;
use SineMacula\Laravel\Sso\Protocols\Saml2\ServiceProviderMetadata;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;

/**
 * Query budgets for the descriptions and the public JWKS, which must not grow
 * with what a connection holds or vary by caller. None of them writes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ServiceProviderDescriptions::class)]
#[CoversClass(ServiceProviderMetadata::class)]
#[CoversClass(RelyingPartyDescription::class)]
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
     * A client secret, an unsupported method, a protocol without such keys and
     * a disabled protocol each read the connection alone.
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
     * `private_key_jwt` reads the connection and its key ring, with no key,
     * one, or a current and a next.
     *
     * @return void
     */
    public function testThePublicKeysAreTwoReadsHoweverManyKeys(): void
    {
        $connection = $this->oidc('private_key_jwt');

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->publicKeysOf($connection->id, 2)->reason);

        $this->addKey($connection, KeyUse::CLIENT_ASSERTION, KeyType::EC);

        self::assertTrue($this->publicKeysOf($connection->id, 2)->isAvailable());

        $this->addKey($connection, KeyUse::CLIENT_ASSERTION, KeyType::EC);

        self::assertTrue($this->publicKeysOf($connection->id, 2)->isAvailable());
    }

    /**
     * SAML metadata reads the connection, then its signing and its encryption
     * keys, with none or a current and a next of each.
     *
     * @return void
     */
    public function testSamlMetadataIsThreeReadsHoweverManyKeys(): void
    {
        config()->set('sso.features.saml2', true);

        $saml = $this->makeConnection(['tenant_id' => self::TENANT, 'protocol' => 'saml2']);
        $bare = $this->describe($saml->id, 3);

        foreach ([KeyUse::SP_SIGNING, KeyUse::SP_SIGNING, KeyUse::SP_ENCRYPTION, KeyUse::SP_ENCRYPTION] as $use) {
            $this->addKey($saml, $use, null);
        }

        $keyed = $this->describe($saml->id, 3);

        self::assertTrue($bare->isAvailable());
        self::assertSame(0, substr_count((string) $bare->body, ':KeyDescriptor '));
        self::assertSame(4, substr_count((string) $keyed->body, ':KeyDescriptor '));
    }

    /**
     * A description refused reads at most the connection: an unknown id,
     * another tenant's connection and a protocol turned off each read it; an
     * empty id reads nothing.
     *
     * @return void
     */
    public function testARefusedDescriptionIsAtMostOneRead(): void
    {
        config()->set('sso.features.saml2', true);

        $other = $this->makeConnection(['tenant_id' => 'tenant-2', 'protocol' => 'saml2']);
        $saml  = $this->makeConnection(['tenant_id' => self::TENANT, 'protocol' => 'saml2']);

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->describe('', 0)->reason);
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->describe('01jbunknownconnection00000', 1)->reason);
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->describe($other->id, 1)->reason);

        config()->set('sso.features.saml2', false);

        self::assertSame(FailureReason::PROTOCOL_UNAVAILABLE, $this->describe($saml->id, 1)->reason);
    }

    /**
     * An OIDC description, by URL or with its keys inline, reads the key ring
     * only for `private_key_jwt`, however many keys; inline keys of a SAML
     * connection are refused on its read.
     *
     * @return void
     */
    public function testAnOidcDescriptionReadsTheKeysOnlyForPrivateKeyJwt(): void
    {
        $secret = $this->oidc('client_secret_basic');
        $keyed  = $this->oidc('private_key_jwt');
        $saml   = $this->makeConnection(['tenant_id' => self::TENANT, 'protocol' => 'saml2']);

        config()->set('sso.features.saml2', true);

        self::assertTrue($this->describe($secret->id, 1)->isAvailable());
        self::assertTrue($this->describeWithInlineKeys($secret->id, 1)->isAvailable());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->describeWithInlineKeys($saml->id, 1)->reason);

        foreach ([1, 2] as $keys) {
            $this->addKey($keyed, KeyUse::CLIENT_ASSERTION, KeyType::EC);

            $inline = $this->describeWithInlineKeys($keyed->id, 2);

            self::assertTrue($this->describe($keyed->id, 2)->isAvailable());
            self::assertSame($keys, substr_count((string) $inline->body, '"kty"'));
        }
    }

    /**
     * The tenant's description of the id, asserted to cost the reads given and
     * no write.
     *
     * @param  string  $id
     * @param  int  $reads
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     */
    private function describe(string $id, int $reads): ServiceProviderDescription
    {
        return $this->assertQueryBudget($reads, 0, fn (): ServiceProviderDescription => $this->descriptions()->describe(self::TENANT, $id));
    }

    /**
     * The tenant's description of the id with its keys inline, asserted to cost
     * the reads given and no write.
     *
     * @param  string  $id
     * @param  int  $reads
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     */
    private function describeWithInlineKeys(string $id, int $reads): ServiceProviderDescription
    {
        return $this->assertQueryBudget($reads, 0, fn (): ServiceProviderDescription => $this->descriptions()->describeWithInlineKeys(self::TENANT, $id));
    }

    /**
     * The id's public keys, asserted to cost the reads given and no write.
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
     * Add a key of the use and type to the connection, current if it is the
     * first of the use.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  ?\SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @return void
     */
    private function addKey(Connection $connection, KeyUse $use, ?KeyType $type): void
    {
        self::assertTrue(app(KeyService::class)->addNext(self::TENANT, $connection->id, $use, Clients::browser(), $type)->isSucceeded());
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
