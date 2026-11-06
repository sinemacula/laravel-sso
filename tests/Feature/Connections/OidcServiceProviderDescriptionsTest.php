<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ClientKey;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
use SineMacula\Laravel\Sso\Protocols\Oidc\RelyingPartyDescription;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Secrets\Secret;
use Tests\Concerns\DumpsValues;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\TestCase;

/**
 * Feature tests for the service provider description helper with an OIDC
 * connection (SSO-5.9, SSO-5.5, SSO-2.7): what the connection registers at its
 * provider, as its driver describes it; a disabled or incomplete connection
 * described too; an unknown connection and another tenant's refused with the
 * same answer, and the tenant matched exactly; the feature off refused; the
 * rotation's keys published; a `private_key_jwt` connection with no key
 * refused; a bound endpoint resolver honoured; no secret; and nothing asked,
 * written or reported.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ServiceProviderDescriptions::class)]
#[CoversClass(RelyingPartyDescription::class)]
final class OidcServiceProviderDescriptionsTest extends TestCase
{
    use DumpsValues, RecordsEventSequences, UsesConnections;

    /** @var string The tenant whose connections are described. */
    private const string TENANT = 'tenant-1';

    /** @var string A connection id no row has. */
    private const string UNKNOWN = '01jbunknownconnection00000';

    /** @var string The client id, which no description names. */
    private const string CLIENT_ID = 'the-client-id-at-the-provider';

    /** @var string The client secret, which no description names. */
    private const string SECRET = 'the-client-secret-never-described';

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract, which describing never asks. */
    private RecordingFreshness $freshness;

    /**
     * Bind a fixed clock and a recording freshness contract, configure OIDC and
     * the endpoints, create the tables, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = new RecordingFreshness;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, $this->freshness);

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');

        $this->usePackageTables();

        $this->startRecordingEvents();
    }

    /**
     * An OIDC connection is described as its driver describes it: the exact
     * client metadata, as JSON, with nothing asked, written or reported.
     *
     * @return void
     */
    public function testDescribesAnOidcConnectionAsItsClientMetadata(): void
    {
        $connection = $this->oidc('client_secret_post');

        $this->startRecordingEvents();

        $writes      = $this->countWrites();
        $description = $this->descriptions()->describe(self::TENANT, $connection->id);

        self::assertTrue($description->isAvailable());
        self::assertNull($description->reason);
        self::assertSame('application/json', $description->contentType);
        self::assertSame(
            '{"redirect_uris":["https://sp.example.test/auth/sso/connections/' . $connection->id . '/callback"],"response_types":["code"],'
            . '"grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_post"}',
            $description->body,
        );
        self::assertEquals(app(ProtocolManager::class)->protocol(OidcDriver::NAME)->describe($connection), $description);
        self::assertSame([], $this->freshness->asked());
        self::assertSame(0, $writes->count);
        $this->assertNoEvents();
    }

    /**
     * A disabled connection, and one with no settings, is described, so it can
     * be registered before it is enabled.
     *
     * @return void
     */
    public function testDescribesADisabledOrIncompleteConnection(): void
    {
        $disabled   = $this->oidc('client_secret_basic', enabled: false);
        $incomplete = $this->makeConnection(['enabled' => false, 'settings' => []]);

        foreach ([$disabled, $incomplete] as $connection) {

            $description = $this->descriptions()->describe(self::TENANT, $connection->id);

            self::assertSame(
                '{"redirect_uris":["https://sp.example.test/auth/sso/connections/' . $connection->id . '/callback"],"response_types":["code"],'
                . '"grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_basic"}',
                $description->body,
            );
        }
    }

    /**
     * Rows of `[tenant, connection id]`: a connection the tenant does not have,
     * as named by the case.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideConnectionsTheTenantDoesNotHave(): iterable
    {
        yield from [
            'an unknown connection'           => [self::TENANT, self::UNKNOWN],
            'another tenant\'s connection'    => [self::TENANT, 'other'],
            'a tenant differing only in case' => ['Tenant-1', 'own'],
            'a tenant with a trailing space'  => ['tenant-1 ', 'own'],
            'an empty connection id'          => [self::TENANT, ''],
            'an overlong connection id'       => [self::TENANT, str_repeat('a', 27)],
        ];
    }

    /**
     * A connection the tenant does not have is `connection_unavailable`, the
     * same answer whether it is unknown or another tenant's, with no fresh
     * authentication asked.
     *
     * @param  string  $tenant
     * @param  string  $connectionId
     * @return void
     */
    #[DataProvider('provideConnectionsTheTenantDoesNotHave')]
    public function testRefusesAConnectionTheTenantDoesNotHave(string $tenant, string $connectionId): void
    {
        $own   = $this->withKey($this->oidc('private_key_jwt'));
        $other = $this->withKey($this->oidc('private_key_jwt', tenant: 'tenant-2'));
        $id    = match ($connectionId) {
            'own'   => $own->id,
            'other' => $other->id,
            default => $connectionId,
        };

        $asked       = $this->freshness->asked();
        $description = $this->descriptions()->describe($tenant, $id);
        $unknown     = $this->descriptions()->describe(self::TENANT, self::UNKNOWN);

        self::assertFalse($description->isAvailable());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $description->reason);
        self::assertNull($description->contentType);
        self::assertNull($description->body);
        self::assertEquals($unknown, $description);
        self::assertEquals(ServiceProviderDescription::unavailable(FailureReason::CONNECTION_UNAVAILABLE), $description);
        self::assertSame($asked, $this->freshness->asked());
    }

    /**
     * Another tenant's connection is described for that tenant, under its own
     * key, so the refusal above is the tenant's, not the connection's.
     *
     * @return void
     */
    public function testDescribesAConnectionForItsOwnTenant(): void
    {
        $other = $this->withKey($this->oidc('private_key_jwt', tenant: 'tenant-2'));

        self::assertFalse($this->descriptions()->describe(self::TENANT, $other->id)->isAvailable());

        $description = $this->descriptions()->describe('tenant-2', $other->id);

        self::assertTrue($description->isAvailable());
        self::assertSame(
            ['https://sp.example.test/auth/sso/connections/' . $other->id . '/callback'],
            self::decoded($description)['redirect_uris'],
        );
    }

    /**
     * A tenant id the connections table cannot hold is the application's
     * mistake, an `InvalidArgumentException`.
     *
     * @return void
     */
    public function testRefusesATenantIdTheTableCannotHold(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A tenant id is 1 to 255 bytes.');

        $this->descriptions()->describe('', self::UNKNOWN);
    }

    /**
     * With the OIDC feature off a connection is `protocol_unavailable`, and
     * described again once it is back on.
     *
     * @return void
     */
    public function testRefusesAConnectionWhileTheFeatureIsOff(): void
    {
        $connection = $this->oidc('client_secret_basic');

        config()->set('sso.features.oidc', false);
        config()->set('sso.features.saml2', true);

        self::assertEquals(
            ServiceProviderDescription::unavailable(FailureReason::PROTOCOL_UNAVAILABLE),
            $this->descriptions()->describe(self::TENANT, $connection->id),
        );

        config()->set('sso.features.oidc', true);

        self::assertTrue($this->descriptions()->describe(self::TENANT, $connection->id)->isAvailable());
    }

    /**
     * A `private_key_jwt` connection with no key of its own has nothing to
     * register: `connection_unavailable`, until a key is added.
     *
     * @return void
     */
    public function testRefusesPrivateKeyJwtWithNoKey(): void
    {
        $connection = $this->oidc('private_key_jwt');

        self::assertEquals(
            ServiceProviderDescription::unavailable(FailureReason::CONNECTION_UNAVAILABLE),
            $this->descriptions()->describe(self::TENANT, $connection->id),
        );

        $this->withKey($connection);

        self::assertSame('application/json', $this->descriptions()->describe(self::TENANT, $connection->id)->contentType);
    }

    /**
     * A rotation shows through the helper: the current key and the next, in
     * that order, the signing algorithm the current key's, and only the next
     * once it is made current.
     *
     * @return void
     */
    public function testPublishesTheRotationsKeys(): void
    {
        $connection = $this->oidc('private_key_jwt');
        $current    = $this->addKey($connection);
        $next       = $this->addKey($connection);
        $during     = self::decoded($this->descriptions()->describeWithInlineKeys(self::TENANT, $connection->id));

        self::assertSame('private_key_jwt', $during['token_endpoint_auth_method']);
        self::assertSame('ES256', $during['token_endpoint_auth_signing_alg']);
        self::assertSame([self::kidOf($current), self::kidOf($next)], self::kidsOf($during));

        app(KeyService::class)->makeCurrent(self::TENANT, $connection->id, $next->id, Clients::browser());

        self::assertSame([self::kidOf($next)], self::kidsOf(self::decoded($this->descriptions()->describeWithInlineKeys(self::TENANT, $connection->id))));
    }

    /**
     * An endpoint resolver the application binds is what the helper's answer
     * names.
     *
     * @return void
     */
    public function testHonorsABoundEndpointResolver(): void
    {
        $this->app?->instance(EndpointResolver::class, new readonly class implements EndpointResolver {
            /**
             * Endpoints only this resolver would build, by the connection's id.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints
             */
            #[\Override]
            public function endpoints(SsoConnection $connection): ConnectionEndpoints
            {
                $url = 'https://own-layout.example/' . $connection->getConnectionId() . '/';

                return new ConnectionEndpoints($url . 'acs', $url . 'oidc', $url . 'entity', $url . 'metadata', $url . 'jwks');
            }
        });

        $connection = $this->oidc('client_secret_basic');

        self::assertSame(
            ['https://own-layout.example/' . $connection->id . '/oidc'],
            self::decoded($this->descriptions()->describe(self::TENANT, $connection->id))['redirect_uris'],
        );
    }

    /**
     * The helper's answer holds neither the client secret, the client id nor
     * the private key, in its body or in any dump.
     *
     * @return void
     */
    public function testShowsNoSecret(): void
    {
        $connection  = $this->oidc('private_key_jwt', self::SECRET);
        $key         = $this->addKey($connection);
        $description = $this->descriptions()->describe(self::TENANT, $connection->id);
        $private     = app(KeyRing::class)->privateKey($connection->id, $key->id);

        self::assertTrue($description->isAvailable());

        foreach ([self::SECRET, self::CLIENT_ID, $private->reveal(), ClientKey::fromPrivateKey($private)->privateJwk()['d']] as $value) {

            self::assertStringNotContainsString($value, (string) $description->body);

            foreach (self::dumps($description) as $dump) {
                self::assertStringNotContainsString($value, $dump);
            }
        }
    }

    /**
     * By default `private_key_jwt` names the public JWKS URL, and the helper's
     * explicit export holds the keys instead, each for its own tenant alone.
     *
     * @return void
     */
    public function testNamesTheJwksUrlAndExportsTheKeysOnlyWhenAsked(): void
    {
        $connection = $this->withKey($this->oidc('private_key_jwt'));
        $byUrl      = self::decoded($this->descriptions()->describe(self::TENANT, $connection->id));
        $inline     = self::decoded($this->descriptions()->describeWithInlineKeys(self::TENANT, $connection->id));

        self::assertSame('https://sp.example.test/auth/sso/connections/' . $connection->id . '/jwks', $byUrl['jwks_uri']);
        self::assertArrayNotHasKey('jwks', $byUrl);
        self::assertArrayHasKey('jwks', $inline);
        self::assertArrayNotHasKey('jwks_uri', $inline);
        self::assertEquals(
            ServiceProviderDescription::unavailable(FailureReason::CONNECTION_UNAVAILABLE),
            $this->descriptions()->describeWithInlineKeys('tenant-2', $connection->id),
        );
    }

    /**
     * The public keys are served by the connection's id alone, of any tenant,
     * holding the current and next keys, with nothing of a secret.
     *
     * @return void
     */
    public function testServesThePublicKeysByTheConnectionsIdAlone(): void
    {
        $connection = $this->oidc('private_key_jwt', self::SECRET);
        $current    = $this->addKey($connection);
        $next       = $this->addKey($connection);

        $this->startRecordingEvents();

        $asked  = $this->freshness->asked();
        $writes = $this->countWrites();
        $keys   = $this->descriptions()->publicKeys($connection->id);

        self::assertSame('application/jwk-set+json', $keys->contentType);
        self::assertSame([self::kidOf($current), self::kidOf($next)], array_column(self::decoded($keys)['keys'], 'kid'));
        self::assertStringNotContainsString(self::SECRET, (string) $keys->body);
        self::assertSame($asked, $this->freshness->asked());
        self::assertSame(0, $writes->count);
        $this->assertNoEvents();
    }

    /**
     * Rows of `[id]`: an id that names no connection, looked up or not.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnknownIds(): iterable
    {
        yield 'unknown' => [self::UNKNOWN];
        yield 'empty' => [''];
        yield 'longer than a ULID' => [str_repeat('a', 27)];
    }

    /**
     * An id that names no connection is answered as one with nothing to serve.
     *
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideUnknownIds')]
    public function testThePublicKeysOfNoConnectionAreUnavailable(string $id): void
    {
        self::assertEquals(ServiceProviderDescription::unavailable(FailureReason::CONNECTION_UNAVAILABLE), $this->descriptions()->publicKeys($id));
    }

    /**
     * An id of another case names no connection, whether the column's collation
     * counts it as equal or not: both ways, nothing is served.
     *
     * @return void
     */
    public function testThePublicKeysOfAnIdOfAnotherCaseAreUnavailable(): void
    {
        $connection  = $this->withKey($this->oidc('private_key_jwt'));
        $unavailable = ServiceProviderDescription::unavailable(FailureReason::CONNECTION_UNAVAILABLE);

        self::assertEquals($unavailable, $this->descriptions()->publicKeys(strtoupper($connection->id)));

        // Stand in for a collation such as MySQL's `_ci`: the statement matches
        // the id asked for, but the row it hands back records another case.
        Connection::retrieved(static function (Connection $found): void {
            $found->setRawAttributes(['id' => strtoupper($found->id)] + $found->getAttributes(), true);
        });

        $statements = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($statements): void {
            $statements->append($query->sql);
        });

        try {
            self::assertEquals($unavailable, $this->descriptions()->publicKeys($connection->id));
            self::assertCount(1, $statements, 'A row of another case must stop at its lookup, before any key is read.');
        } finally {
            Event::forget('eloquent.retrieved: ' . Connection::class);
        }
    }

    /**
     * A protocol with no such keys answers `connection_unavailable`, and a
     * protocol switched off `protocol_unavailable`.
     *
     * @return void
     */
    public function testThePublicKeysDependOnTheProtocol(): void
    {
        config()->set('sso.features.saml2', true);

        $saml = $this->makeConnection(['tenant_id' => self::TENANT, 'protocol' => 'saml2']);

        self::assertEquals(ServiceProviderDescription::unavailable(FailureReason::CONNECTION_UNAVAILABLE), $this->descriptions()->publicKeys($saml->id));
        self::assertEquals(ServiceProviderDescription::unavailable(FailureReason::CONNECTION_UNAVAILABLE), $this->descriptions()->describeWithInlineKeys(self::TENANT, $saml->id));

        $connection = $this->withKey($this->oidc('private_key_jwt'));

        config()->set('sso.features.oidc', false);

        self::assertEquals(ServiceProviderDescription::unavailable(FailureReason::PROTOCOL_UNAVAILABLE), $this->descriptions()->publicKeys($connection->id));
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

    /**
     * An OIDC connection authenticating by the method, of the tenant given and
     * with the client secret given, if any.
     *
     * @param  string  $method
     * @param  ?string  $secret
     * @param  bool  $enabled
     * @param  string  $tenant
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function oidc(string $method, ?string $secret = null, bool $enabled = true, string $tenant = self::TENANT): Connection
    {
        return $this->makeConnection([
            'tenant_id' => $tenant,
            'enabled'   => $enabled,
            'settings'  => [
                'issuer'                 => 'https://op.example.test',
                'authorization_endpoint' => 'https://op.example.test/authorize',
                'token_endpoint'         => 'https://op.example.test/token',
                'jwks_uri'               => 'https://op.example.test/jwks',
                'client_id'              => self::CLIENT_ID,
                'client_authentication'  => $method,
            ],
            'secrets' => $secret === null ? null : app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret($secret)]),
        ]);
    }

    /**
     * The connection, given a key of its own.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function withKey(Connection $connection): Connection
    {
        $this->addKey($connection);

        return $connection;
    }

    /**
     * Generate a P-256 client assertion key for the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Keys\KeySummary
     */
    private function addKey(Connection $connection): KeySummary
    {
        $key = app(KeyService::class)->addNext($connection->tenant_id, $connection->id, KeyUse::CLIENT_ASSERTION, Clients::browser(), KeyType::EC)->key;

        self::assertNotNull($key);

        return $key;
    }

    /**
     * Count every statement that writes, from now on.
     *
     * @return object{count: int}
     */
    private function countWrites(): object
    {
        $writes = new class {
            /** @var int The statements that wrote. */
            public int $count = 0;
        };

        DB::listen(static function (QueryExecuted $query) use ($writes): void {

            if (preg_match('/^\s*(?:insert|update|delete|replace)\b/i', $query->sql) !== 1) {
                return;
            }

            $writes->count++;
        });

        return $writes;
    }

    /**
     * The description's body, read.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription  $description
     * @return array<string, mixed>
     */
    private static function decoded(ServiceProviderDescription $description): array
    {
        /** @var array<string, mixed> */
        return json_decode((string) $description->body, true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * The `kid` of each key of the client metadata's JWKS, in order.
     *
     * @param  array<string, mixed>  $metadata
     * @return list<string>
     */
    private static function kidsOf(array $metadata): array
    {
        /** @var array{keys: list<array<string, string>>} $jwks */
        $jwks = $metadata['jwks'];

        return array_column($jwks['keys'], 'kid');
    }

    /**
     * The `kid` of the key's public half.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeySummary  $key
     * @return string
     */
    private static function kidOf(KeySummary $key): string
    {
        return ClientKey::publicJwk((string) $key->key->publicKey)['kid'];
    }
}
