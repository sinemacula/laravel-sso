<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\ServiceProviderMetadata;

use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Testing\Saml\FakeServiceProvider;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/service-provider-metadata.md` (SSO-5.9,
 * SSO-12.5), on the shared example harness: the description of a tenant's
 * connection, the metadata route and the public keys route, each run as the
 * application runs it, the routes over HTTP. A SAML connection is described
 * before its identity provider's settings are given and while it is disabled,
 * and an OIDC connection as JSON; another tenant's connection and an unknown
 * one are refused `connection_unavailable`, and a connection whose protocol is
 * off `protocol_unavailable`. The metadata route serves the description at the
 * URL its entity id names, and answers each refusal with `404`; the public keys
 * route serves an OIDC `private_key_jwt` connection's keys at the `jwks_uri`
 * its description names, whatever the host, and answers `404` for a connection
 * with no keys to serve.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ServiceProviderDescriptions::class)]
#[CoversClass(ServiceProviderDescription::class)]
#[CoversClass(FakeServiceProvider::class)]
final class ServiceProviderMetadataExampleTest extends ExampleTestCase
{
    /** @var string Where the package builds every connection's URLs, as the harness configures it. */
    private const string BASE_URL = 'https://sp.example.test';

    /** @var string A host the application serves for another tenant, which has no connection. */
    private const string OTHER_HOST = 'https://other.example.test';

    /** @var string A connection id no tenant has. */
    private const string UNKNOWN = '01jc3yq6v8h2m9t4n7r5w1k0xs';

    /** @var string The SAML metadata's content type. */
    private const string SAML_METADATA = 'application/samlmetadata+xml';

    /** @var string The public keys' content type. */
    private const string JWK_SET = 'application/jwk-set+json';

    /**
     * Serve the metadata route behind the application's tenancy middleware, and
     * the public keys route with no tenant.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(TenantFromHost::class)->group(__DIR__ . '/metadata-route.php');
        Route::group([], __DIR__ . '/jwks-route.php');
    }

    /**
     * A SAML connection with no identity provider settings, never enabled, is
     * described by its service provider metadata, whose entity id is the URL
     * the metadata route serves.
     *
     * @return void
     */
    public function testASamlConnectionIsDescribedBeforeItIsComplete(): void
    {
        $connectionId = $this->samlConnection();

        $described = self::described(self::TENANT, $connectionId);

        self::assertSame(self::SAML_METADATA, $described['content_type']);
        self::assertNull($described['reason']);

        $sp = FakeServiceProvider::fromMetadata((string) $described['metadata']);

        self::assertSame(self::BASE_URL . "/auth/sso/connections/{$connectionId}/metadata", $sp->entityId);
        self::assertSame(self::BASE_URL . "/auth/sso/connections/{$connectionId}/assertions", $sp->assertionConsumerService);
        self::assertFalse(app(ConnectionService::class)->get(self::TENANT, $connectionId)?->usable);
    }

    /**
     * An OIDC connection is described by what its driver describes: client
     * metadata as JSON, naming the callback and its client authentication.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnOidcConnectionIsDescribedByItsDriver(): void
    {
        $connectionId = (string) app(ConnectionService::class)->create(self::TENANT, 'oidc', 'Acme OIDC', Clients::browser())->connection?->id;

        $described = self::described(self::TENANT, $connectionId);
        $metadata  = self::decoded($described['metadata']);

        self::assertSame('application/json', $described['content_type']);
        self::assertSame([self::BASE_URL . "/auth/sso/connections/{$connectionId}/callback"], $metadata['redirect_uris']);
        self::assertSame('client_secret_basic', $metadata['token_endpoint_auth_method']);
        self::assertArrayNotHasKey('jwks_uri', $metadata);
    }

    /**
     * Another tenant's connection is refused exactly as an unknown one, with
     * `connection_unavailable` and no document.
     *
     * @return void
     */
    public function testAnotherTenantsConnectionIsRefusedAsAnUnknownOne(): void
    {
        $connectionId = $this->samlConnection();
        $refusal      = ['content_type' => null, 'metadata' => null, 'reason' => FailureReason::CONNECTION_UNAVAILABLE];

        self::assertSame($refusal, self::described(TenantFromHost::TENANTS['other.example.test'], $connectionId));
        self::assertSame($refusal, self::described(self::TENANT, self::UNKNOWN));
    }

    /**
     * A connection whose protocol is switched off is refused
     * `protocol_unavailable`.
     *
     * @return void
     */
    public function testAConnectionWhoseProtocolIsOffIsRefused(): void
    {
        $connectionId = $this->samlConnection();

        config()->set('sso.features.saml2', false);

        self::assertSame(
            ['content_type' => null, 'metadata' => null, 'reason' => FailureReason::PROTOCOL_UNAVAILABLE],
            self::described(self::TENANT, $connectionId),
        );
    }

    /**
     * The metadata route serves the description's exact bytes at the URL the
     * entity id names, with its content type and cache lifetime.
     *
     * @return void
     */
    public function testTheMetadataRouteServesTheDescriptionAtItsEntityId(): void
    {
        $connectionId = $this->samlConnection();
        $described    = self::described(self::TENANT, $connectionId);
        $entityId     = FakeServiceProvider::fromMetadata((string) $described['metadata'])->entityId;

        $served = $this->get($entityId)->assertOk();

        $served->assertHeader('Content-Type', self::SAML_METADATA);
        $served->assertHeader('Cache-Control', 'max-age=3600, public');
        self::assertSame($described['metadata'], $served->baseResponse->getContent());
    }

    /**
     * The metadata route answers `404` for another tenant's connection, an
     * unknown one, and one whose protocol is off, serving no metadata.
     *
     * @return void
     */
    public function testTheMetadataRouteAnswersEveryRefusalWithNotFound(): void
    {
        $connectionId = $this->samlConnection();
        $path         = "/auth/sso/connections/{$connectionId}/metadata";

        $refusals = [
            $this->get(self::OTHER_HOST . $path),
            $this->get(self::BASE_URL . '/auth/sso/connections/' . self::UNKNOWN . '/metadata'),
        ];

        config()->set('sso.features.saml2', false);

        $refusals[] = $this->get(self::BASE_URL . $path);

        foreach ($refusals as $refused) {
            $refused->assertNotFound();
            self::assertNotSame(self::SAML_METADATA, $refused->headers->get('Content-Type'));
        }
    }

    /**
     * An OIDC connection using `private_key_jwt` is described naming its
     * `jwks_uri`, and the public keys route serves its one public key there,
     * with no private member, the same from any host.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testThePublicKeysRouteServesTheKeysAtTheJwksUri(): void
    {
        $connectionId = $this->privateKeyJwtConnection();
        $jwksUri      = self::decoded(self::described(self::TENANT, $connectionId)['metadata'])['jwks_uri'];

        self::assertSame(self::BASE_URL . "/auth/sso/connections/{$connectionId}/jwks", $jwksUri);

        $served = $this->get($jwksUri)->assertOk();

        $served->assertHeader('Content-Type', self::JWK_SET);
        $served->assertHeader('Cache-Control', 'max-age=300, public');
        self::assertSame(app(ServiceProviderDescriptions::class)->publicKeys($connectionId)->body, $served->baseResponse->getContent());
        self::assertCount(1, (array) $served->json('keys'));
        self::assertSame(['EC', 'ES256', 'sig'], [$served->json('keys.0.kty'), $served->json('keys.0.alg'), $served->json('keys.0.use')]);
        self::assertArrayNotHasKey('d', (array) $served->json('keys.0'));
        self::assertSame($served->baseResponse->getContent(), $this->get(self::OTHER_HOST . "/auth/sso/connections/{$connectionId}/jwks")->assertOk()->baseResponse->getContent());
    }

    /**
     * The public keys route answers `404` for a client secret connection, a
     * SAML connection, an unknown one, and a `private_key_jwt` connection with
     * no key yet.
     *
     * @return void
     */
    public function testThePublicKeysRouteAnswersNotFoundWithNoKeysToServe(): void
    {
        $connections = app(ConnectionService::class);

        $connectionIds = [
            (string) $connections->create(self::TENANT, 'oidc', 'Client secret OIDC', Clients::browser())->connection?->id,
            $this->samlConnection(),
            self::UNKNOWN,
            (string) $connections->create(self::TENANT, 'oidc', 'Keyless OIDC', Clients::browser(), ['client_authentication' => 'private_key_jwt'])->connection?->id,
        ];

        foreach ($connectionIds as $connectionId) {
            $this->get(self::BASE_URL . "/auth/sso/connections/{$connectionId}/jwks")->assertNotFound();
        }
    }

    /**
     * The tenant's SAML connection, with no identity provider settings and
     * never enabled.
     *
     * @return string
     */
    private function samlConnection(): string
    {
        $created = app(ConnectionService::class)->create(self::TENANT, 'saml2', 'Acme SAML', Clients::browser());

        self::assertNotNull($created->connection);

        return $created->connection->id;
    }

    /**
     * The tenant's OIDC connection using `private_key_jwt`, with a P-256 key
     * added.
     *
     * @return string
     */
    private function privateKeyJwtConnection(): string
    {
        $created = app(ConnectionService::class)->create(self::TENANT, 'oidc', 'Acme OIDC', Clients::browser(), ['client_authentication' => 'private_key_jwt']);

        self::assertNotNull($created->connection);
        self::assertTrue(app(KeyService::class)->addNext(self::TENANT, $created->connection->id, KeyUse::CLIENT_ASSERTION, Clients::browser(), KeyType::EC)->isSucceeded());

        return $created->connection->id;
    }

    /**
     * What the guide's description answers for the tenant's connection.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @return array{content_type: ?string, metadata: ?string, reason: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}
     */
    private static function described(string $tenantId, string $connectionId): array
    {
        return self::describedWith(['tenant_id' => $tenantId, 'connection_id' => $connectionId]);
    }

    /**
     * The guide's description, run with its input.
     *
     * @param  array{tenant_id: string, connection_id: string}  $input
     * @return array{content_type: ?string, metadata: ?string, reason: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}
     */
    private static function describedWith(array $input): array
    {
        /** @var array{content_type: ?string, metadata: ?string, reason: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason} */
        return require __DIR__ . '/describe.php';
    }

    /**
     * A JSON description, decoded.
     *
     * @param  ?string  $json
     * @return array<string, mixed>
     *
     * @throws \JsonException
     */
    private static function decoded(?string $json): array
    {
        $decoded = json_decode((string) $json, true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($decoded);

        /** @var array<string, mixed> */
        return $decoded;
    }
}
