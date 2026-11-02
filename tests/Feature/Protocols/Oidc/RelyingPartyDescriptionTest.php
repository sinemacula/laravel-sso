<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Oidc;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Base64Url;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ClientKey;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\JoseAdapter;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\PublicKeyEncoding;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;
use SineMacula\Laravel\Sso\Protocols\Oidc\RelyingPartyDescription;
use SineMacula\Laravel\Sso\Protocols\Oidc\TokenExchange;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\JwsSigner;
use Tests\Concerns\DumpsValues;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Protocols\IdentifiedConnection;
use Tests\TestCase;

/**
 * Feature tests for what an administrator registers at the OpenID provider
 * (SSO-5.9, SSO-2.7, SSO-5.5): the exact JSON for each client authentication,
 * checked against the published RFC 7638 thumbprint; the published keys through
 * a rotation, current and then next; `PS256` and `ES256` by key type; the `kid`
 * the client assertion is signed under; no private member and no secret, in the
 * body or in a dump; the callback only the endpoint resolver builds; nothing to
 * describe with no key; nothing reported or written; and the fake provider
 * accepting the package's client assertion with the key published.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RelyingPartyDescription::class)]
final class RelyingPartyDescriptionTest extends TestCase
{
    use DumpsValues, RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The tenant whose connections are described. */
    private const string TENANT = 'tenant-1';

    /** @var string The client id, which no description names. */
    private const string CLIENT_ID = 'the-client-id-at-the-provider';

    /** @var string The client secret, which no description names. */
    private const string SECRET = 'the-client-secret-never-described';

    /** @var string The PKCE verifier of the exchanged request. */
    private const string VERIFIER = 'the-pkce-verifier-of-the-exchanged-request-1';

    /** @var string The modulus of RFC 7638 §3.1's example key. */
    private const string RSA_N = '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXA'
        . 'rwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lF'
        . 'd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw';

    /** @var string The thumbprint RFC 7638 §3.1 gives for its example key. */
    private const string RSA_KID = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

    /** @var string The `x` of RFC 7517 Appendix A.1's example P-256 key. */
    private const string EC_X = 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4';

    /** @var string The `y` of RFC 7517 Appendix A.1's example P-256 key. */
    private const string EC_Y = '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM';

    /** @var string The RFC 7638 thumbprint of that P-256 key. */
    private const string EC_KID = 'cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s';

    /** @var list<string> The members of a private JWK no description holds. */
    private const array PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi'];

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract, which describing never asks. */
    private RecordingFreshness $freshness;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher a token request is sent through. */
    private FakeFetcher $fetcher;

    /**
     * Bind a fixed clock, a recording freshness contract and the fake fetcher,
     * configure OIDC and the endpoints, create the tables, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock     = new FixedClock('2026-11-01T09:30:00Z');
        $this->freshness = new RecordingFreshness;
        $this->fetcher   = new FakeFetcher;

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Freshness::class, $this->freshness);
        $this->app?->instance(Fetcher::class, $this->fetcher);

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');

        $this->createConnectionTables();
        $this->createFlowTables();

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
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * Rows of `[method]`: a client authentication that carries a secret.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSecretMethods(): iterable
    {
        yield from [
            'basic' => ['client_secret_basic'],
            'post'  => ['client_secret_post'],
        ];
    }

    /**
     * A client secret method is described exactly: the callback, the code flow
     * and the method, in that order, slashes unescaped, and no key, even when
     * the connection holds one.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideSecretMethods')]
    public function testDescribesAClientSecretMethodExactly(string $method): void
    {
        $connection = $this->connection($method);

        $this->storeKey($connection, self::ecPem(), KeyType::EC, KeyState::CURRENT);

        $description = $this->describe($connection);

        self::assertTrue($description->isAvailable());
        self::assertNull($description->reason);
        self::assertSame('application/json', $description->contentType);
        self::assertSame(
            '{"redirect_uris":["https://sp.example.test/auth/sso/connections/' . $connection->id . '/callback"],'
            . '"response_types":["code"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"' . $method . '"}',
            $description->body,
        );
    }

    /**
     * A connection with no settings is described with the default client
     * authentication, as it would authenticate.
     *
     * @return void
     */
    public function testDescribesTheDefaultClientAuthentication(): void
    {
        $connection = $this->makeConnection();

        self::assertSame('client_secret_basic', self::decoded($this->describe($connection))['token_endpoint_auth_method']);
    }

    /**
     * `private_key_jwt` with an RSA key is described exactly, with RFC 7638's
     * example key under the thumbprint the RFC gives for it.
     *
     * @return void
     */
    public function testDescribesPrivateKeyJwtExactlyWithAnRsaKey(): void
    {
        $connection = $this->connection('private_key_jwt');

        $this->storeKey($connection, self::rsaPem(), KeyType::RSA, KeyState::CURRENT);

        $description = $this->describe($connection);

        self::assertSame('application/json', $description->contentType);
        self::assertSame(
            '{"redirect_uris":["https://sp.example.test/auth/sso/connections/' . $connection->id . '/callback"],'
            . '"response_types":["code"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"private_key_jwt",'
            . '"token_endpoint_auth_signing_alg":"PS256","jwks":{"keys":[' . self::rsaJwk() . ']}}',
            $description->body,
        );
    }

    /**
     * `private_key_jwt` with a P-256 key is described exactly.
     *
     * @return void
     */
    public function testDescribesPrivateKeyJwtExactlyWithAnEcKey(): void
    {
        $connection = $this->connection('private_key_jwt');

        $this->storeKey($connection, self::ecPem(), KeyType::EC, KeyState::CURRENT);

        self::assertSame(
            '{"redirect_uris":["https://sp.example.test/auth/sso/connections/' . $connection->id . '/callback"],'
            . '"response_types":["code"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"private_key_jwt",'
            . '"token_endpoint_auth_signing_alg":"ES256","jwks":{"keys":[' . self::ecJwk() . ']}}',
            $this->describe($connection)->body,
        );
    }

    /**
     * During a rotation the current key is listed first and the next second,
     * whichever was stored first, each with its own algorithm, and the signing
     * algorithm is the current key's alone.
     *
     * @return void
     */
    public function testListsTheCurrentKeyThenTheNext(): void
    {
        $esCurrent = $this->connection('private_key_jwt');

        $this->storeKey($esCurrent, self::rsaPem(), KeyType::RSA, KeyState::NEXT);
        $this->storeKey($esCurrent, self::ecPem(), KeyType::EC, KeyState::CURRENT);

        $psCurrent = $this->connection('private_key_jwt');

        $this->storeKey($psCurrent, self::rsaPem(), KeyType::RSA, KeyState::CURRENT);
        $this->storeKey($psCurrent, self::ecPem(), KeyType::EC, KeyState::NEXT);

        self::assertSame(
            '{"redirect_uris":["https://sp.example.test/auth/sso/connections/' . $esCurrent->id . '/callback"],'
            . '"response_types":["code"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"private_key_jwt",'
            . '"token_endpoint_auth_signing_alg":"ES256","jwks":{"keys":[' . self::ecJwk() . ',' . self::rsaJwk() . ']}}',
            $this->describe($esCurrent)->body,
        );
        self::assertSame(
            '{"redirect_uris":["https://sp.example.test/auth/sso/connections/' . $psCurrent->id . '/callback"],'
            . '"response_types":["code"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"private_key_jwt",'
            . '"token_endpoint_auth_signing_alg":"PS256","jwks":{"keys":[' . self::rsaJwk() . ',' . self::ecJwk() . ']}}',
            $this->describe($psCurrent)->body,
        );
    }

    /**
     * A next key with no current one, which the key service never leaves but a
     * stored row can, is published under its own algorithm: it is what will
     * sign.
     *
     * @return void
     */
    public function testPublishesANextKeyWithNoCurrentOne(): void
    {
        $connection = $this->connection('private_key_jwt');

        $this->storeKey($connection, self::ecPem(), KeyType::EC, KeyState::NEXT);

        $metadata = self::decoded($this->describe($connection));

        self::assertSame('ES256', $metadata['token_endpoint_auth_signing_alg']);
        self::assertSame([self::EC_KID], self::kidsOf($metadata));
    }

    /**
     * The description follows a rotation by the key service: the current key
     * alone; the current and the next, in that order; once the next is made
     * current, it alone, the replaced key retiring and gone; and it stays gone
     * once retired.
     *
     * @return void
     */
    public function testFollowsARotation(): void
    {
        $connection = $this->connection('private_key_jwt');
        $first      = $this->addKey($connection, KeyType::EC);
        $kid        = self::kidOf($first);

        self::assertSame(KeyState::CURRENT, $first->state);
        self::assertSame([$kid], self::kidsOf(self::decoded($this->describe($connection))));

        $second    = $this->addKey($connection, KeyType::EC);
        $secondKid = self::kidOf($second);

        self::assertSame(KeyState::NEXT, $second->state);
        self::assertNotSame($kid, $secondKid);
        self::assertSame([$kid, $secondKid], self::kidsOf(self::decoded($this->describe($connection))));

        $promoted = app(KeyService::class)->makeCurrent(self::TENANT, $connection->id, $second->id);

        self::assertSame(KeyState::RETIRING, $promoted->previous?->state);

        $afterPromotion = $this->describe($connection);

        self::assertSame([$secondKid], self::kidsOf(self::decoded($afterPromotion)));

        self::assertTrue(app(KeyService::class)->retire(self::TENANT, $connection->id, $first->id)->isSucceeded());

        self::assertSame($afterPromotion->body, $this->describe($connection)->body);
    }

    /**
     * A retiring key alone has nothing to publish, however long its overlap has
     * to run.
     *
     * @return void
     */
    public function testARetiringKeyIsNeverPublished(): void
    {
        $connection = $this->connection('private_key_jwt');

        $this->storeKey($connection, self::ecPem(), KeyType::EC, KeyState::RETIRING);

        self::assertEquals(ServiceProviderDescription::unavailable(FailureReason::CONNECTION_UNAVAILABLE), $this->describe($connection));
    }

    /**
     * Rows of `[type, algorithm]`: a key type and what it signs with.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Keys\Enums\KeyType, 1: string}>
     */
    public static function provideKeyTypes(): iterable
    {
        yield from [
            'rsa' => [KeyType::RSA, 'PS256'],
            'ec'  => [KeyType::EC, 'ES256'],
        ];
    }

    /**
     * A generated key is described under its type's algorithm, with exactly the
     * public members of its type, for signatures.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  string  $algorithm
     * @return void
     */
    #[DataProvider('provideKeyTypes')]
    public function testAGeneratedKeyGivesItsTypesAlgorithm(KeyType $type, string $algorithm): void
    {
        $connection = $this->connection('private_key_jwt');

        $this->addKey($connection, $type);

        $metadata = self::decoded($this->describe($connection));
        $jwk      = self::jwksOf($metadata)[0];

        self::assertSame($algorithm, $metadata['token_endpoint_auth_signing_alg']);
        self::assertSame($type === KeyType::RSA ? ['e', 'kty', 'n', 'kid', 'use', 'alg'] : ['crv', 'kty', 'x', 'y', 'kid', 'use', 'alg'], array_keys($jwk));
        self::assertSame([$algorithm, 'sig'], [$jwk['alg'], $jwk['use']]);
    }

    /**
     * The `kid` published is the one the client assertion is signed under, with
     * the algorithm published, and is the thumbprint of the key's public half;
     * the signature verifies with the key stored.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  string  $algorithm
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideKeyTypes')]
    public function testTheKidIsTheOneTheClientAssertionIsSignedUnder(KeyType $type, string $algorithm): void
    {
        $connection = $this->connection('private_key_jwt');
        $key        = $this->addKey($connection, $type);
        $publicPem  = (string) $key->key->publicKey;
        $assertion  = app(JoseAdapter::class)->signClientAssertion(
            self::CLIENT_ID,
            'https://op.example.test/token',
            app(KeyRing::class)->privateKey($connection->id, $key->id),
            $this->clock->now(),
        );
        $header = json_decode(JwsSigner::decode(explode('.', $assertion->reveal())[0]), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($header);

        $kid = ClientKey::publicJwk($publicPem)['kid'];

        self::assertSame($header['kid'], $kid);
        self::assertSame($algorithm, $header['alg']);
        self::assertSame([$kid], self::kidsOf(self::decoded($this->describe($connection))));
        self::assertSame(self::thumbprint(self::jwksOf(self::decoded($this->describe($connection)))[0]), $kid);
        self::assertTrue(JwsSigner::verify($assertion->reveal(), $publicPem));
    }

    /**
     * No private member, private key, ciphertext, client secret, client id or
     * other key id ever appears, in the body or in any dump of the description,
     * for a key of either type while the connection also holds a client secret.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  string  $algorithm
     * @return void
     */
    #[DataProvider('provideKeyTypes')]
    public function testHoldsNoPrivateMemberAndNoSecret(KeyType $type, string $algorithm): void
    {
        unset($algorithm);

        $connection = $this->connection('private_key_jwt', self::SECRET);
        $key        = $this->addKey($connection, $type);
        $next       = $this->addKey($connection, $type);
        $metadata   = self::decoded($this->describe($connection));

        self::assertCount(2, self::jwksOf($metadata));
        self::assertSame([], array_values(array_intersect(self::PRIVATE_MEMBERS, self::membersOf($metadata))));

        $forbidden = [
            self::SECRET,
            self::CLIENT_ID,
            'client_id',
            'client_secret',
            ...self::ciphertextsOf($connection),
            ...$this->privateValuesOf($connection, $key),
            ...$this->privateValuesOf($connection, $next),
        ];

        $this->assertNothingShown($this->describe($connection), $forbidden);
    }

    /**
     * A client secret method shows neither the secret, its ciphertext nor the
     * client id, in the body or in any dump; its name is the method's alone.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideSecretMethods')]
    public function testAClientSecretMethodHoldsNoSecret(string $method): void
    {
        $connection = $this->connection($method, self::SECRET);

        $this->assertNothingShown($this->describe($connection), [
            self::SECRET,
            self::CLIENT_ID,
            'client_id',
            ...self::ciphertextsOf($connection),
        ]);
    }

    /**
     * The callback is exactly the endpoint resolver's, following the configured
     * base URL and path pattern, whatever the request says.
     *
     * @return void
     */
    public function testTheCallbackIsTheEndpointResolvers(): void
    {
        config()->set('sso.endpoints.base_url', 'https://other.example.test/base');
        config()->set('sso.endpoints.paths.callback', '/sign-in/{connection}/done');

        $this->app?->instance('request', Request::create('https://evil.example/forged', 'GET', server: [
            'HTTP_HOST'             => 'evil.example',
            'HTTP_X_FORWARDED_HOST' => 'evil.example',
        ]));

        $connection = $this->connection('client_secret_basic');
        $callback   = app(EndpointResolver::class)->endpoints($connection)->callback;

        self::assertSame('https://other.example.test/base/sign-in/' . $connection->id . '/done', $callback);
        self::assertSame([$callback], self::decoded($this->describe($connection))['redirect_uris']);
    }

    /**
     * An endpoint resolver the application binds is honoured.
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

                return new ConnectionEndpoints($url . 'acs', $url . 'oidc?x=y', $url . 'entity', $url . 'metadata', $url . 'jwks');
            }
        });

        $connection = $this->connection('client_secret_post');

        self::assertSame(
            '{"redirect_uris":["https://own-layout.example/' . $connection->id . '/oidc?x=y"],"response_types":["code"],'
            . '"grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_post"}',
            $this->describe($connection)->body,
        );
    }

    /**
     * Rows of `[method]`: every client authentication.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideEveryMethod(): iterable
    {
        yield from self::provideSecretMethods();
        yield 'private key' => ['private_key_jwt'];
    }

    /**
     * An endpoint configuration that cannot build the callback fails closed,
     * with or without a key to publish.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideEveryMethod')]
    public function testAnEndpointConfigurationThatCannotBuildTheCallbackIsRefused(string $method): void
    {
        config()->set('sso.endpoints.base_url', 'http://sp.example.test');

        $connection = $this->connection($method);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`sso.endpoints.base_url` must be');

        $this->describe($connection);
    }

    /**
     * `private_key_jwt` with no key of its own is `connection_unavailable`: no
     * key at all, a key of another use, or another connection's.
     *
     * @return void
     */
    public function testIsUnavailableWithoutAKey(): void
    {
        $connection  = $this->connection('private_key_jwt');
        $other       = $this->connection('private_key_jwt');
        $unavailable = ServiceProviderDescription::unavailable(FailureReason::CONNECTION_UNAVAILABLE);

        self::assertEquals($unavailable, $this->describe($connection));

        $this->storeKey($connection, self::rsaPem(), KeyType::RSA, KeyState::CURRENT, KeyUse::SP_SIGNING);
        $this->storeKey($other, self::ecPem(), KeyType::EC, KeyState::CURRENT);

        $description = $this->describe($connection);

        self::assertEquals($unavailable, $description);
        self::assertFalse($description->isAvailable());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $description->reason);
        self::assertNull($description->contentType);
        self::assertNull($description->body);
        self::assertTrue($this->describe($other)->isAvailable());
    }

    /**
     * A published key the package would not sign with fails closed, naming
     * nothing of the key, rather than being left out or described.
     *
     * @return void
     */
    public function testAKeyThePackageWouldNotSignWithIsRefused(): void
    {
        $connection = $this->connection('private_key_jwt');

        $this->storeKey($connection, FakeSigningKey::ec('other-curve', 'P-384')->publicKeyPem, KeyType::EC, KeyState::CURRENT);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A client assertion key is an RSA key of at least 2048 bits or an elliptic curve key on P-256.');

        $this->describe($connection);
    }

    /**
     * A disabled connection, and one with none of the provider's settings, is
     * described exactly as an enabled, complete one with the same method.
     *
     * @return void
     */
    public function testDescribesAConnectionWhateverItHolds(): void
    {
        $connection = $this->connection('private_key_jwt');

        $this->storeKey($connection, self::ecPem(), KeyType::EC, KeyState::CURRENT);

        $enabled = $this->describe($connection)->body;

        $connection->forceFill(['enabled' => false])->save();

        self::assertSame($enabled, $this->describe($connection)->body);

        $connection->forceFill(['settings' => ['client_authentication' => 'private_key_jwt']])->save();

        self::assertFalse(app(ProtocolManager::class)->protocol(OidcDriver::NAME)->isComplete($connection));
        self::assertSame($enabled, $this->describe($connection)->body);
    }

    /**
     * Rows of `[method]`: a client authentication stored past the settings'
     * validation, which the package does not support.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideUnsupportedMethods(): iterable
    {
        yield 'another RFC 8705 method' => ['tls_client_auth'];
        yield 'none' => ['none'];
        yield 'of another case' => ['CLIENT_SECRET_BASIC'];
        yield 'empty' => [''];
        yield 'bytes JSON cannot hold' => ["\xB1"];
        yield 'a number' => [1];
    }

    /**
     * A method the package does not support is refused in every document, so
     * nothing registers a client that could never authenticate.
     *
     * @param  mixed  $method
     * @return void
     */
    #[DataProvider('provideUnsupportedMethods')]
    public function testAnUnsupportedMethodIsRefused(mixed $method): void
    {
        $connection  = new IdentifiedConnection('01jbstoredmethod0000000000', settings: ['client_authentication' => $method]);
        $unavailable = ServiceProviderDescription::unavailable(FailureReason::SETTINGS_INVALID);

        self::assertEquals($unavailable, self::driver()->describe($connection));
        self::assertEquals($unavailable, self::driver()->describeWithInlineKeys($connection));
        self::assertEquals($unavailable, self::driver()->publicKeys($connection));
    }

    /**
     * `private_key_jwt` names the public JWKS URL by default, with the signing
     * algorithm and no keys, exactly.
     *
     * @return void
     */
    public function testNamesThePublicJwksUrlByDefault(): void
    {
        $connection = $this->connection('private_key_jwt');

        $this->storeKey($connection, self::rsaPem(), KeyType::RSA, KeyState::CURRENT);

        $description = self::driver()->describe($connection);

        self::assertSame('application/json', $description->contentType);
        self::assertSame(
            '{"redirect_uris":["https://sp.example.test/auth/sso/connections/' . $connection->id . '/callback"],"response_types":["code"],'
            . '"grant_types":["authorization_code"],"token_endpoint_auth_method":"private_key_jwt",'
            . '"token_endpoint_auth_signing_alg":"PS256","jwks_uri":"https://sp.example.test/auth/sso/connections/' . $connection->id . '/jwks"}',
            $description->body,
        );
    }

    /**
     * Neither document holds both a `jwks_uri` and a `jwks`.
     *
     * @return void
     */
    public function testNeverNamesBothInOneDocument(): void
    {
        $connection = $this->connection('private_key_jwt');

        $this->addKey($connection, KeyType::EC);

        $byUrl  = self::decoded(self::driver()->describe($connection));
        $inline = self::decoded(self::driver()->describeWithInlineKeys($connection));

        self::assertArrayHasKey('jwks_uri', $byUrl);
        self::assertArrayNotHasKey('jwks', $byUrl);
        self::assertArrayHasKey('jwks', $inline);
        self::assertArrayNotHasKey('jwks_uri', $inline);
    }

    /**
     * A client secret method names neither a key nor a URL for one.
     *
     * @return void
     */
    public function testAClientSecretMethodNamesNoJwksUrl(): void
    {
        $metadata = self::decoded(self::driver()->describe($this->connection('client_secret_post')));

        self::assertArrayNotHasKey('jwks_uri', $metadata);
        self::assertArrayNotHasKey('jwks', $metadata);
    }

    /**
     * The URL named is the bound resolver's.
     *
     * @return void
     */
    public function testTheJwksUrlIsTheEndpointResolvers(): void
    {
        $connection = $this->connection('private_key_jwt');

        $this->addKey($connection, KeyType::EC);

        config()->set('sso.endpoints.paths.jwks', '/oidc/{connection}/keys.json');

        self::assertSame('https://sp.example.test/oidc/' . $connection->id . '/keys.json', self::decoded(self::driver()->describe($connection))['jwks_uri']);
    }

    /**
     * The public JWKS holds the current key then the next, exactly, as its own
     * media type, and holds no private member.
     *
     * @return void
     */
    public function testThePublicKeysHoldTheCurrentThenTheNext(): void
    {
        $connection = $this->connection('private_key_jwt');

        $this->storeKey($connection, self::rsaPem(), KeyType::RSA, KeyState::CURRENT);
        $this->storeKey($connection, self::ecPem(), KeyType::EC, KeyState::NEXT);

        $keys = self::driver()->publicKeys($connection);

        self::assertSame('application/jwk-set+json', $keys->contentType);
        self::assertSame('{"keys":[' . self::rsaJwk() . ',' . self::ecJwk() . ']}', $keys->body);
    }

    /**
     * The public JWKS follows a rotation by the key service, which is what a
     * `jwks_uri` relies on: the current key alone; the current and the next, in
     * that order; once the next is made current, it alone, the replaced key
     * retiring and gone; and it stays gone once retired.
     *
     * @return void
     */
    public function testThePublicKeysFollowARotation(): void
    {
        $connection = $this->connection('private_key_jwt');
        $first      = $this->addKey($connection, KeyType::EC);
        $kids       = fn (): array => self::kidsOf(['jwks' => self::decoded(self::driver()->publicKeys($connection))]);

        self::assertSame([self::kidOf($first)], $kids());

        $second = $this->addKey($connection, KeyType::EC);

        self::assertSame([self::kidOf($first), self::kidOf($second)], $kids());

        $promoted = app(KeyService::class)->makeCurrent(self::TENANT, $connection->id, $second->id);

        self::assertSame(KeyState::RETIRING, $promoted->previous?->state);
        self::assertSame([self::kidOf($second)], $kids());

        self::assertTrue(app(KeyService::class)->retire(self::TENANT, $connection->id, $first->id)->isSucceeded());

        self::assertSame([self::kidOf($second)], $kids());
    }

    /**
     * The public JWKS of a connection with nothing to serve is unavailable: no
     * key yet, or a client secret method.
     *
     * @return void
     */
    public function testThePublicKeysAreUnavailableWithNothingToServe(): void
    {
        $unavailable = ServiceProviderDescription::unavailable(FailureReason::CONNECTION_UNAVAILABLE);

        self::assertEquals($unavailable, self::driver()->publicKeys($this->connection('private_key_jwt')));
        self::assertEquals($unavailable, self::driver()->publicKeys($this->connection('client_secret_basic', self::SECRET)));
    }

    /**
     * Rows of `[algorithm, type, signing algorithm]`: a pinned algorithm that
     * fits its key: the assertion's header, the JWK's `alg` and the description
     * agree, under the same `kid`.
     *
     * @return iterable<string, array{0: ?string, 1: \SineMacula\Laravel\Sso\Keys\Enums\KeyType, 2: string}>
     */
    public static function provideFittingAlgorithms(): iterable
    {
        yield 'RSA, none pinned' => [null, KeyType::RSA, 'PS256'];
        yield 'RSA, PS256' => ['PS256', KeyType::RSA, 'PS256'];
        yield 'RSA, RS256' => ['RS256', KeyType::RSA, 'RS256'];
        yield 'P-256, none pinned' => [null, KeyType::EC, 'ES256'];
        yield 'P-256, ES256' => ['ES256', KeyType::EC, 'ES256'];
    }

    /**
     * The header, the published `alg` and the description all follow the pinned
     * algorithm, the `kid` not moving, and the provider verifies the assertion.
     *
     * @param  ?string  $pinned
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  string  $algorithm
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideFittingAlgorithms')]
    public function testThePinnedAlgorithmIsUsedEverywhere(?string $pinned, KeyType $type, string $algorithm): void
    {
        $provider   = $this->provider();
        $connection = $this->providerConnection($provider);
        $key        = $this->addKey($connection, $type);

        $connection->forceFill(['settings' => [...$connection->settings, 'client_assertion_algorithm' => $pinned]])->save();

        $metadata = self::decoded(self::driver()->describe($connection));
        $inline   = self::jwksOf(self::decoded(self::driver()->describeWithInlineKeys($connection)))[0];
        $public   = json_decode((string) self::driver()->publicKeys($connection)->body, true, 512, JSON_THROW_ON_ERROR);
        $options  = OidcOptions::of($connection);
        $sent     = app(TokenExchange::class)->credentials($connection, $options);

        self::assertNotNull($sent);
        self::assertIsArray($public);

        $header = json_decode(JwsSigner::decode(explode('.', $sent->secret())[0]), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($header);
        self::assertSame($algorithm, $metadata['token_endpoint_auth_signing_alg']);
        self::assertSame($algorithm, $inline['alg']);
        self::assertSame($algorithm, $public['keys'][0]['alg'] ?? null);
        self::assertSame($algorithm, $header['alg']);
        self::assertSame(ClientKey::publicJwk((string) $key->key->publicKey)['kid'], $header['kid']);
        self::assertSame($inline['kid'], $header['kid']);

        $provider->register(self::CLIENT_ID, 'private_key_jwt', null, self::pemOf($inline));

        self::assertSame(200, $this->exchange($provider, $connection));
    }

    /**
     * Rows of `[pinned, type]`: a pinned algorithm a key cannot sign under, or
     * that the package does not sign with.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Sso\Keys\Enums\KeyType}>
     */
    public static function provideUnfittingAlgorithms(): iterable
    {
        yield 'RS256 and a P-256 key' => ['RS256', KeyType::EC];
        yield 'PS256 and a P-256 key' => ['PS256', KeyType::EC];
        yield 'ES256 and an RSA key' => ['ES256', KeyType::RSA];
        yield 'ES384 and a P-256 key' => ['ES384', KeyType::EC];
        yield 'RS384 and an RSA key' => ['RS384', KeyType::RSA];
    }

    /**
     * An algorithm stored past validation that its key cannot sign under, or
     * the package does not sign with, is `settings_invalid` in every document,
     * and the connection is not complete.
     *
     * @param  string  $pinned
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @return void
     */
    #[DataProvider('provideUnfittingAlgorithms')]
    public function testAnAlgorithmThatDoesNotFitIsRefused(string $pinned, KeyType $type): void
    {
        $connection = $this->connection('private_key_jwt');

        $this->addKey($connection, $type);

        $connection->forceFill(['settings' => [...$connection->settings, 'client_assertion_algorithm' => $pinned]])->save();

        $invalid = ServiceProviderDescription::unavailable(FailureReason::SETTINGS_INVALID);

        self::assertEquals($invalid, self::driver()->describe($connection));
        self::assertEquals($invalid, self::driver()->describeWithInlineKeys($connection));
        self::assertEquals($invalid, self::driver()->publicKeys($connection));
        self::assertFalse(self::driver()->isComplete($connection));
    }

    /**
     * A next key that does not fit is refused as a current one is.
     *
     * @return void
     */
    public function testANextKeyThatDoesNotFitIsRefused(): void
    {
        $connection = $this->connection('private_key_jwt');

        $this->storeKey($connection, self::rsaPem(), KeyType::RSA, KeyState::CURRENT);
        $this->storeKey($connection, self::ecPem(), KeyType::EC, KeyState::NEXT);

        $connection->forceFill(['settings' => [...$connection->settings, 'client_assertion_algorithm' => 'RS256']])->save();

        self::assertEquals(ServiceProviderDescription::unavailable(FailureReason::SETTINGS_INVALID), self::driver()->describe($connection));
    }

    /**
     * What a connection holds is validated short of requiring it complete: a
     * valid method and key with none of the provider's settings is described,
     * so it can be registered before it is enabled.
     *
     * @return void
     */
    public function testRegisteringBeforeEnablingStillWorks(): void
    {
        $connection = $this->connection('private_key_jwt');

        $this->addKey($connection, KeyType::EC);

        $connection->forceFill(['enabled' => false, 'settings' => ['client_authentication' => 'private_key_jwt', 'client_assertion_algorithm' => 'ES256']])->save();

        self::assertTrue(self::driver()->describe($connection)->isAvailable());
        self::assertTrue(self::driver()->publicKeys($connection)->isAvailable());
        self::assertFalse(self::driver()->isComplete($connection));
    }

    /**
     * Describing reports nothing, asks for no fresh authentication and writes
     * nothing, and the same state gives the same bytes.
     *
     * @return void
     */
    public function testDescribingChangesAndReportsNothing(): void
    {
        $connection = $this->connection('private_key_jwt');

        $this->storeKey($connection, self::rsaPem(), KeyType::RSA, KeyState::CURRENT);
        $this->storeKey($connection, self::ecPem(), KeyType::EC, KeyState::NEXT);

        $this->startRecordingEvents();

        $writes = $this->countWrites();
        $first  = $this->describe($connection);
        $second = $this->describe($connection);

        self::assertSame($first->body, $second->body);
        self::assertSame(0, $writes->count);
        self::assertSame([], $this->freshness->asked());
        $this->assertNoEvents();
    }

    /**
     * The driver answers this description, from the connection's settings as
     * they are now.
     *
     * @return void
     */
    public function testTheDriverAnswersThisDescription(): void
    {
        $connection = $this->connection('client_secret_post');

        self::assertEquals(
            app(RelyingPartyDescription::class)->describe($connection, OidcOptions::of($connection)),
            $this->describe($connection),
        );
    }

    /**
     * The fake provider, registered with the public key the description
     * publishes, accepts the package's client assertion at its token endpoint,
     * and refuses it with any other key registered.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  string  $algorithm
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideKeyTypes')]
    public function testTheProviderVerifiesTheAssertionWithThePublishedKey(KeyType $type, string $algorithm): void
    {
        $provider   = $this->provider();
        $connection = $this->providerConnection($provider);

        $this->addKey($connection, $type);

        $metadata = self::decoded($this->describe($connection));

        self::assertSame($algorithm, $metadata['token_endpoint_auth_signing_alg']);

        $provider->register(self::CLIENT_ID, 'private_key_jwt', null, self::pemOf(self::jwksOf($metadata)[0]));

        self::assertSame(200, $this->exchange($provider, $connection));

        $someoneElse = $type === KeyType::RSA ? FakeSigningKey::rsa('someone-else') : FakeSigningKey::ec('someone-else');

        $provider->register(self::CLIENT_ID, 'private_key_jwt', null, $someoneElse->publicKeyPem);

        self::assertSame(401, $this->exchange($provider, $connection));
    }

    /**
     * Registering the next key the description publishes is what makes the
     * rotation seamless: the provider refuses the current key's assertion once
     * it holds only the next, and accepts the assertions signed once the next
     * is made current.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheNextKeyPublishedVerifiesOnceItIsMadeCurrent(): void
    {
        $provider   = $this->provider();
        $connection = $this->providerConnection($provider);

        $this->addKey($connection, KeyType::EC);

        $next = $this->addKey($connection, KeyType::EC);
        $jwks = self::jwksOf(self::decoded($this->describe($connection)));

        $provider->register(self::CLIENT_ID, 'private_key_jwt', null, self::pemOf($jwks[0]));

        self::assertSame(200, $this->exchange($provider, $connection));

        $provider->register(self::CLIENT_ID, 'private_key_jwt', null, self::pemOf($jwks[1]));

        self::assertSame(401, $this->exchange($provider, $connection));

        app(KeyService::class)->makeCurrent(self::TENANT, $connection->id, $next->id);

        self::assertSame(200, $this->exchange($provider, $connection));
    }

    /**
     * What the description shows for the connection with its keys in the
     * document, through its driver.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     */
    private function describe(SsoConnection $connection): ServiceProviderDescription
    {
        return self::driver()->describeWithInlineKeys($connection);
    }

    /**
     * The OIDC driver.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver
     */
    private static function driver(): OidcDriver
    {
        $driver = app(ProtocolManager::class)->protocol(OidcDriver::NAME);

        self::assertInstanceOf(OidcDriver::class, $driver);

        return $driver;
    }

    /**
     * An enabled, complete connection authenticating by the method, with the
     * client secret given, if any.
     *
     * @param  string  $method
     * @param  ?string  $secret
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connection(string $method, ?string $secret = null): Connection
    {
        return $this->makeConnection([
            'enabled'  => true,
            'settings' => [
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
     * Store a key's public half on the connection, as the row the key ring
     * reads.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $publicKeyPem
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return \SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private function storeKey(Connection $connection, string $publicKeyPem, KeyType $type, KeyState $state, KeyUse $use = KeyUse::CLIENT_ASSERTION): ConnectionKey
    {
        $key = new ConnectionKey;

        $key->forceFill([
            'connection_id'   => $connection->id,
            'use'             => $use,
            'state'           => $state,
            'key_type'        => $type,
            'key_bits'        => $type === KeyType::RSA ? 2048 : 256,
            'public_key'      => $publicKeyPem,
            'private_key'     => app(SecretEncrypter::class)->encrypt('not-read-by-the-description'),
            'fingerprint'     => hash('sha256', $publicKeyPem),
            'made_current_at' => $state === KeyState::NEXT ? null : $this->clock->now(),
            'retiring_until'  => $state === KeyState::RETIRING ? $this->clock->now()->addWeek() : null,
        ])->save();

        return $key;
    }

    /**
     * Generate a key of the type for the connection, by the key service.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @return \SineMacula\Laravel\Sso\Keys\KeySummary
     */
    private function addKey(Connection $connection, KeyType $type): KeySummary
    {
        $key = app(KeyService::class)->addNext(self::TENANT, $connection->id, KeyUse::CLIENT_ASSERTION, $type)->key;

        self::assertNotNull($key);

        return $key;
    }

    /**
     * Every value of the key's private half: its private JWK's members, its PEM
     * and its stored ciphertext, with what would identify its row.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\KeySummary  $key
     * @return list<string>
     */
    private function privateValuesOf(Connection $connection, KeySummary $key): array
    {
        $secret  = app(KeyRing::class)->privateKey($connection->id, $key->id);
        $private = ClientKey::fromPrivateKey($secret)->privateJwk();
        $values  = array_values(array_intersect_key($private, array_flip(self::PRIVATE_MEMBERS)));
        $row     = ConnectionKey::query()->whereKey($key->id)->firstOrFail();

        self::assertNotSame([], $values);

        return [
            ...$values,
            $secret->reveal(),
            (string) preg_replace('/\s+/', '', str_replace(['-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----'], '', $secret->reveal())),
            (string) $row->private_key,
            $key->id,
            (string) $key->key->fingerprint,
        ];
    }

    /**
     * Assert none of the values appears in the description's body or in any
     * dump of the description.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription  $description
     * @param  list<string>  $forbidden
     * @return void
     */
    private function assertNothingShown(ServiceProviderDescription $description, array $forbidden): void
    {
        self::assertTrue($description->isAvailable());

        foreach ($forbidden as $value) {

            self::assertNotSame('', $value);
            self::assertStringNotContainsString($value, (string) $description->body);

            foreach (self::dumps($description) as $dump) {
                self::assertStringNotContainsString($value, $dump);
            }
        }
    }

    /**
     * A fake provider, serving its endpoints on the fake fetcher.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider
     */
    private function provider(): FakeOpenIdProvider
    {
        return (new FakeOpenIdProvider(clock: $this->clock))->serve($this->fetcher);
    }

    /**
     * A `private_key_jwt` connection at the provider.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function providerConnection(FakeOpenIdProvider $provider): Connection
    {
        return $this->makeConnection([
            'enabled'  => true,
            'settings' => [
                'issuer'                 => $provider->issuer,
                'authorization_endpoint' => $provider->endpoint('authorization'),
                'token_endpoint'         => $provider->endpoint('token'),
                'jwks_uri'               => $provider->endpoint('jwks'),
                'client_id'              => self::CLIENT_ID,
                'client_authentication'  => 'private_key_jwt',
            ],
        ]);
    }

    /**
     * Have the provider grant a code for the connection's callback, exchange it
     * with the package's client assertion, and answer the token endpoint's HTTP
     * status.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return ?int
     *
     * @throws \Random\RandomException
     */
    private function exchange(FakeOpenIdProvider $provider, Connection $connection): ?int
    {
        $exchange      = app(TokenExchange::class);
        $options       = OidcOptions::of($connection);
        $authorization = $provider->authorize($provider->endpoint('authorization') . '?' . http_build_query([
            'redirect_uri'   => app(EndpointResolver::class)->endpoints($connection)->callback,
            'code_challenge' => JwsSigner::encode(hash('sha256', self::VERIFIER, true)),
            'nonce'          => 'the-nonce',
            'scope'          => 'openid',
        ]));
        $credentials = $exchange->credentials($connection, $options);

        self::assertNotNull($credentials);
        self::assertSame(CredentialKind::PRIVATE_KEY_JWT, $credentials->kind);

        return $exchange->send($connection, $options, $authorization->code, $this->consumed(), $credentials)->statusCode;
    }

    /**
     * The request the code answers.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\ConsumedRequest
     */
    private function consumed(): ConsumedRequest
    {
        $encrypter = app(SecretEncrypter::class);

        return new ConsumedRequest(
            purpose: Purpose::SIGN_IN,
            application: 'web',
            reference: RequestReference::fromString('Sq8tVv3w0kLmNoPqRsTuVwXyZ0123456'),
            startedAt: $this->clock->now(),
            codeVerifier: $encrypter->encrypt(self::VERIFIER),
            encrypter: $encrypter,
        );
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
     * The keys of the client metadata's JWKS.
     *
     * @param  array<string, mixed>  $metadata
     * @return list<array<string, string>>
     */
    private static function jwksOf(array $metadata): array
    {
        /** @var array{keys: list<array<string, string>>} $jwks */
        $jwks = $metadata['jwks'];

        return $jwks['keys'];
    }

    /**
     * The `kid` of each key of the client metadata's JWKS, in order.
     *
     * @param  array<string, mixed>  $metadata
     * @return list<string>
     */
    private static function kidsOf(array $metadata): array
    {
        return array_column(self::jwksOf($metadata), 'kid');
    }

    /**
     * The ciphertext of each secret the connection stores.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return list<string>
     */
    private static function ciphertextsOf(Connection $connection): array
    {
        /** @var array<string, string> $stored */
        $stored = json_decode((string) $connection->secrets, true, 512, JSON_THROW_ON_ERROR);

        self::assertNotSame([], $stored);

        return array_values($stored);
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

    /**
     * Every member name at any depth of the value.
     *
     * @param  array<array-key, mixed>  $value
     * @return list<string>
     */
    private static function membersOf(array $value): array
    {
        $members = [];

        foreach ($value as $name => $member) {
            $members = [...$members, ...(is_string($name) ? [$name] : []), ...(is_array($member) ? self::membersOf($member) : [])];
        }

        return $members;
    }

    /**
     * The RFC 7638 thumbprint of the JWK, worked out from its required members
     * alone, independently of the package.
     *
     * @param  array<string, string>  $jwk
     * @return string
     */
    private static function thumbprint(array $jwk): string
    {
        $required = $jwk['kty'] === 'RSA'
            ? ['e' => $jwk['e'], 'kty' => 'RSA', 'n' => $jwk['n']]
            : ['crv' => $jwk['crv'], 'kty' => 'EC', 'x' => $jwk['x'], 'y' => $jwk['y']];

        return JwsSigner::encode(hash('sha256', json_encode($required, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), true));
    }

    /**
     * The PEM public key a provider reads from the JWK, as one registered from
     * the description would.
     *
     * @param  array<string, string>  $jwk
     * @return string
     */
    private static function pemOf(array $jwk): string
    {
        $key = $jwk['kty'] === 'RSA'
            ? PublicKeyEncoding::rsa((string) Base64Url::decode($jwk['n']), (string) Base64Url::decode($jwk['e']))
            : PublicKeyEncoding::ec($jwk['crv'], (string) Base64Url::decode($jwk['x']), (string) Base64Url::decode($jwk['y']));

        self::assertNotNull($key);

        return $key['pem'];
    }

    /**
     * The PEM of RFC 7638's example key.
     *
     * @return string
     */
    private static function rsaPem(): string
    {
        return self::pemOf(['kty' => 'RSA', 'n' => self::RSA_N, 'e' => 'AQAB']);
    }

    /**
     * The PEM of RFC 7517's example P-256 key.
     *
     * @return string
     */
    private static function ecPem(): string
    {
        return self::pemOf(['kty' => 'EC', 'crv' => 'P-256', 'x' => self::EC_X, 'y' => self::EC_Y]);
    }

    /**
     * RFC 7638's example key as the description writes it.
     *
     * @return string
     */
    private static function rsaJwk(): string
    {
        return '{"e":"AQAB","kty":"RSA","n":"' . self::RSA_N . '","kid":"' . self::RSA_KID . '","use":"sig","alg":"PS256"}';
    }

    /**
     * RFC 7517's example P-256 key as the description writes it.
     *
     * @return string
     */
    private static function ecJwk(): string
    {
        return '{"crv":"P-256","kty":"EC","x":"' . self::EC_X . '","y":"' . self::EC_Y . '","kid":"' . self::EC_KID . '","use":"sig","alg":"ES256"}';
    }
}
