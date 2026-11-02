<?php

declare(strict_types = 1);

namespace Tests\Feature\Endpoints;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Endpoints\ConfiguredEndpointResolver;
use SineMacula\Laravel\Sso\Endpoints\EndpointSettings;
use SineMacula\Laravel\Sso\Endpoints\Enums\Endpoint;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\Fixtures\Protocols\IdentifiedConnection;
use Tests\TestCase;

/**
 * Feature tests for the default endpoint resolver: each endpoint built from the
 * configured base URL, its path pattern and the connection's id, the entity id
 * being the metadata URL, never anything of the request, and a malformed
 * setting failing closed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfiguredEndpointResolver::class)]
#[CoversClass(EndpointSettings::class)]
final class ConfiguredEndpointResolverTest extends TestCase
{
    /** @var string The id the example connection has. */
    private const string ID = '01jbexampleconnection00000';

    /**
     * Configure a base URL.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.endpoints.base_url', 'https://api.example.com');
    }

    /**
     * The default resolver is the one bound, and builds every endpoint with the
     * default patterns.
     *
     * @return void
     */
    public function testBuildsEachEndpoint(): void
    {
        $endpoints = app(EndpointResolver::class)->endpoints(new ExampleConnection);

        self::assertInstanceOf(ConfiguredEndpointResolver::class, app(EndpointResolver::class));
        self::assertSame([
            'assertion_consumer_service' => 'https://api.example.com/auth/sso/connections/' . self::ID . '/assertions',
            'callback'                   => 'https://api.example.com/auth/sso/connections/' . self::ID . '/callback',
            'entity_id'                  => 'https://api.example.com/auth/sso/connections/' . self::ID . '/metadata',
            'metadata'                   => 'https://api.example.com/auth/sso/connections/' . self::ID . '/metadata',
            'jwks'                       => 'https://api.example.com/auth/sso/connections/' . self::ID . '/jwks',
        ], $endpoints->jsonSerialize());
    }

    /**
     * A base URL's path prefix is kept, and its trailing slashes dropped, so no
     * endpoint holds `//`; a loopback base URL is allowed for development.
     *
     * @return void
     */
    public function testKeepsTheBaseUrlsPathPrefix(): void
    {
        $resolver = app(EndpointResolver::class);

        config()->set('sso.endpoints.base_url', 'https://api.example.com/v1/');

        self::assertSame('https://api.example.com/v1/auth/sso/connections/' . self::ID . '/callback', $resolver->endpoints(new ExampleConnection)->callback);

        config()->set('sso.endpoints.base_url', 'https://api.example.com//');

        self::assertSame('https://api.example.com/auth/sso/connections/' . self::ID . '/callback', $resolver->endpoints(new ExampleConnection)->callback);

        config()->set('sso.endpoints.base_url', 'http://127.0.0.1:8000');

        self::assertSame('http://127.0.0.1:8000/auth/sso/connections/' . self::ID . '/callback', $resolver->endpoints(new ExampleConnection)->callback);
    }

    /**
     * Each endpoint follows its own pattern, read on each call.
     *
     * @return void
     */
    public function testFollowsEachPattern(): void
    {
        config()->set('sso.endpoints.paths', [
            'assertion_consumer_service' => '/saml/{connection}/acs',
            'callback'                   => '/oidc/{connection}',
            'metadata'                   => '/saml/{connection}.xml',
            'jwks'                       => '/oidc/{connection}/keys.json',
        ]);

        $endpoints = app(EndpointResolver::class)->endpoints(new ExampleConnection);

        self::assertSame('https://api.example.com/saml/' . self::ID . '/acs', $endpoints->url(Endpoint::ASSERTION_CONSUMER_SERVICE));
        self::assertSame('https://api.example.com/oidc/' . self::ID, $endpoints->url(Endpoint::CALLBACK));
        self::assertSame('https://api.example.com/saml/' . self::ID . '.xml', $endpoints->url(Endpoint::METADATA));
        self::assertSame('https://api.example.com/saml/' . self::ID . '.xml', $endpoints->entityId);
        self::assertSame('https://api.example.com/oidc/' . self::ID . '/keys.json', $endpoints->url(Endpoint::JWKS));
    }

    /**
     * The connection's id is percent-encoded into the path.
     *
     * @return void
     */
    public function testEncodesTheConnectionsId(): void
    {
        $endpoints = app(EndpointResolver::class)->endpoints(new IdentifiedConnection('a b/c'));

        self::assertSame('https://api.example.com/auth/sso/connections/a%20b%2Fc/assertions', $endpoints->assertionConsumerService);
    }

    /**
     * The request being served changes nothing: neither its host nor a
     * forwarded host or scheme moves an endpoint.
     *
     * @return void
     */
    public function testNeverReadsTheRequest(): void
    {
        $this->app?->instance('request', Request::create('http://attacker.example/x', 'POST', server: [
            'HTTP_HOST'              => 'attacker.example',
            'HTTP_X_FORWARDED_HOST'  => 'attacker.example',
            'HTTP_X_FORWARDED_PROTO' => 'http',
        ]));

        $endpoints = app(EndpointResolver::class)->endpoints(new ExampleConnection);

        self::assertSame('https://api.example.com/auth/sso/connections/' . self::ID . '/assertions', $endpoints->assertionConsumerService);
    }

    /**
     * A malformed base URL or pattern, or a connection with no id, fails closed
     * naming the key.
     *
     * @return void
     */
    public function testAMalformedSettingFailsClosed(): void
    {
        $resolver  = app(EndpointResolver::class);
        $failures  = [];
        $malformed = [
            ['sso.endpoints.base_url', null],
            ['sso.endpoints.base_url', 'https://api.example.com?x=1'],
            ['sso.endpoints.paths.callback', '/oidc/callback'],
        ];

        foreach ($malformed as [$key, $value]) {

            config()->set('sso.endpoints.base_url', 'https://api.example.com');
            config()->set('sso.endpoints.paths.callback', '/auth/sso/connections/{connection}/callback');
            config()->set($key, $value);

            try {
                $resolver->endpoints(new ExampleConnection);
            } catch (\InvalidArgumentException $exception) {
                $failures[] = strstr($exception->getMessage(), ' must', true);
            }
        }

        self::assertSame(['`sso.endpoints.base_url`', '`sso.endpoints.base_url`', '`sso.endpoints.paths.callback`'], $failures);

        config()->set('sso.endpoints.paths.callback', '/auth/sso/connections/{connection}/callback');

        $this->expectExceptionObject(new \InvalidArgumentException('A connection\'s endpoints are built from its id, which is empty.'));

        $resolver->endpoints(new IdentifiedConnection(''));
    }
}
