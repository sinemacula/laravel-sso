<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Foundation\Http\Middleware\Concerns\ExcludesPaths;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;
use SineMacula\Laravel\Sso\Events\ConnectionCreated;
use SineMacula\Laravel\Sso\Events\ConnectionDeleted;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Sessions\AuthenticationContext;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use Tests\Integration\Examples\ExampleTestCase;
use Tests\Integration\Examples\Routes\Application\ConnectionTenants;
use Tests\Integration\Examples\Routes\Application\SignIns;
use Tests\Integration\Examples\Routes\Application\User;

/**
 * The route layout of `docs/guides/example-application.md`, run over HTTP.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationContext::class)]
#[CoversClass(AuthorizationRequestService::class)]
#[CoversClass(CompletionService::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(ServiceProviderDescriptions::class)]
final class RouteLayoutExampleTest extends ExampleTestCase
{
    /** @var string Where the routes are served from, with Laravel's API prefix. */
    private const string BASE_URL = 'https://sp.example.test/api';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The tenant's SAML identity provider. */
    private FakeSamlIdentityProvider $idp;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var \Tests\Integration\Examples\Routes\Application\SignIns The application's sign-ins. */
    private SignIns $signIns;

    /** @var \Tests\Integration\Examples\Routes\Application\User The person the application knows. */
    private User $person;

    /**
     * Register the routes under the API prefix and make the SAML connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        // @snippet-start route-base-url
        config()->set('sso.endpoints.base_url', 'https://sp.example.test/api');
        // @snippet-end route-base-url
        Schema::create(ConnectionTenants::TABLE, static function (Blueprint $table): void {
            $table->string('connection_id')->primary();
            $table->string('tenant_id');
        });

        // @snippet-start route-tenants
        Event::listen(ConnectionCreated::class, [ConnectionTenants::class, 'remember']);
        Event::listen(ConnectionDeleted::class, [ConnectionTenants::class, 'forget']);

        // Who may manage the single sign-on of the tenant they are active in is
        // the application's decision
        Gate::define('manage-sso', static fn (User $user): bool => $user->administersSso());
        // @snippet-end route-tenants
        $this->signIns = new SignIns($this->sessions, $this->clock);
        $this->instance(SignIns::class, $this->signIns);

        Route::prefix('api')->group(__DIR__ . '/routes.php');

        $this->idp          = new FakeSamlIdentityProvider;
        $this->connectionId = $this->makeSamlConnection($this->idp);
        $this->person       = User::of('person-1', self::TENANT);
    }

    /**
     * Drop the application's table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(ConnectionTenants::TABLE);

        parent::tearDown();
    }

    /**
     * A person links, signs in and re-authenticates through the routes.
     *
     * @return void
     */
    public function testLinkingSigningInAndReauthenticatingThroughTheRoutes(): void
    {
        $linkId = $this->linkOverHttp();

        $start      = $this->startOverHttp('/api/auth/sso/authorization-requests');
        $redemption = $this->redemptionOf($this->completeOverHttp($start), $start);
        $signedIn   = $this->postJson('/api/auth/sessions', $redemption)->assertOk();

        self::assertSame('pending', $signedIn->json('status'));
        self::assertStringContainsString('no-store', (string) $signedIn->headers->get('Cache-Control'));
        $this->postJson('/api/auth/sessions', $redemption)->assertStatus(400)->assertExactJson(['error' => 'replayed']);

        $sessionId = $this->signIns->sessionOf(self::text($signedIn, 'token')) ?? self::fail('The credential names no session.');

        // The session is as fresh as the provider says: it authenticated the
        // person a minute before it answered
        self::assertSame('2026-11-01T09:29:00Z', $this->sessions->authenticatedAt($sessionId)?->toIso8601ZuluString());

        // How the session began, projected from the provenance written with it
        $context = $this->signIns->context($sessionId);

        self::assertSame($this->connectionId, $context[AuthenticationContext::CONNECTION]);
        self::assertSame(self::TENANT, $context[AuthenticationContext::TENANT]);
        self::assertSame('saml2', $context[AuthenticationContext::PROTOCOL]);
        self::assertSame($linkId, $context[AuthenticationContext::LINK]);
        self::assertSame('link_purpose', $context[AuthenticationContext::LINK_PROVENANCE]);
        self::assertSame([], $context[AuthenticationContext::PROVIDER_AMR]);
        self::assertSame([], $this->signIns->context('a-session-the-package-did-not-establish'));

        $this->clock->advance(3600);
        $this->actingAs(User::of('person-1', self::TENANT, $sessionId));

        $start = $this->startOverHttp('/api/auth/sso/reauthentications/authorization-requests');

        $this->postJson('/api/auth/sso/reauthentications', $this->redemptionOf($this->completeOverHttp($start), $start))->assertOk();

        self::assertSame('2026-11-01T10:30:00Z', $this->sessions->authenticatedAt($sessionId)?->toIso8601ZuluString());
        $renewed = $this->signIns->context($sessionId);
        $began   = $renewed[AuthenticationContext::PROVIDER_AUTH_TIME];

        // The renewal leaves the provenance of the sign-in alone
        self::assertSame($context, $renewed);
        self::assertSame('2026-11-01T09:29:00.000000Z', $began);

        $this->actingAs(User::of('person-1', self::TENANT, 'session-elsewhere'))
            ->postJson('/api/auth/sso/reauthentications/authorization-requests', ['application' => self::APPLICATION, 'connection' => $this->connectionId])
            ->assertStatus(400)
            ->assertExactJson(['error' => 'session_ineligible']);
    }

    /**
     * Each endpoint fixes its purpose and ignores a `purpose` in the body.
     *
     * @return void
     */
    public function testEachEndpointFixesItsPurpose(): void
    {
        $this->linkOverHttp();

        $start = $this->startOverHttp('/api/auth/sso/authorization-requests', ['purpose' => 'link']);

        $this->postJson('/api/auth/sessions', $this->redemptionOf($this->completeOverHttp($start), $start))
            ->assertOk()
            ->assertJsonPath('status', 'pending');

        $start = $this->startOverHttp('/api/auth/sso/authorization-requests', ['purpose' => 'link']);

        $this->actingAs($this->person)
            ->postJson('/api/auth/sso/links', $this->redemptionOf($this->completeOverHttp($start), $start))
            ->assertStatus(400)
            ->assertExactJson(['error' => 'purpose_mismatch']);

        $start = $this->startOverHttp('/api/auth/sso/links/authorization-requests', ['purpose' => 'sign_in']);

        $this->postJson('/api/auth/sessions', $this->redemptionOf($this->completeOverHttp($start), $start))
            ->assertStatus(400)
            ->assertExactJson(['error' => 'purpose_mismatch']);

        $this->postJson('/api/auth/sso/authorization-requests', ['application' => self::APPLICATION, 'email' => 'person@example.com'])
            ->assertStatus(400)
            ->assertExactJson(['error' => 'feature_disabled']);
    }

    /**
     * The OIDC callback route completes a flow once and rejects a replay.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheCallbackRouteCompletesAnOidcFlow(): void
    {
        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);

        $this->actingAs($this->person);

        $start    = $this->startOverHttp('/api/auth/sso/links/authorization-requests', ['connection' => $connectionId]);
        $callback = '/api/auth/sso/connections/' . $connectionId . '/callback?' . $provider->authorize(self::navigationUrl($start))->query();
        $redirect = $this->redirectOf($this->get($callback), 302);

        self::assertSame($start['reference'], $redirect->reference);
        $this->postJson('/api/auth/sso/links', ['connection' => $connectionId] + $this->redemptionOf($redirect, $start))->assertCreated();
        $this->get($callback)->assertStatus(400)->assertHeaderMissing('Location');
    }

    /**
     * The metadata route serves a known connection's metadata and 404s others.
     *
     * @return void
     */
    public function testTheMetadataRouteServesTheConnectionsMetadata(): void
    {
        $metadata = $this->get('/api/auth/sso/connections/' . $this->connectionId . '/metadata')->assertOk();

        self::assertSame('application/samlmetadata+xml', $metadata->headers->get('Content-Type'));
        self::assertStringContainsString(self::BASE_URL . '/auth/sso/connections/' . $this->connectionId . '/assertions', (string) $metadata->baseResponse->getContent());
        $this->get('/api/auth/sso/connections/01jbz3k7m9q2w8e4r6t1y5u0ia/metadata')->assertNotFound();
    }

    /**
     * The caller lists and removes only their own links.
     *
     * @return void
     */
    public function testTheCallerListsAndRemovesTheirOwnLinks(): void
    {
        $this->getJson('/api/auth/sso/links')->assertUnauthorized();

        $linkId = $this->linkOverHttp();

        $this->getJson('/api/auth/sso/links')->assertOk()->assertJsonCount(1)->assertJsonPath('0.id', $linkId);
        $this->actingAs(User::of('person-2', self::TENANT))->deleteJson('/api/auth/sso/links/' . $linkId)->assertNotFound();
        $this->actingAs($this->person)->deleteJson('/api/auth/sso/links/' . $linkId)->assertOk()->assertJsonPath('removed', true);
        $this->getJson('/api/auth/sso/links')->assertOk()->assertJsonCount(0);
    }

    /**
     * Connection management is authorised and scoped to the caller's tenant.
     *
     * @return void
     */
    public function testManagingConnectionsIsAuthorisedAndScopedToTheCallersTenant(): void
    {
        $connection = [
            'protocol'     => 'oidc',
            'display_name' => 'Acme Google Workspace',
            'preset'       => 'google',
            'settings'     => ['client_id' => 'acme-client', 'client_secret' => 'acme-secret'],
        ];

        $this->postJson('/api/auth/sso/connections', $connection)->assertUnauthorized();
        $this->actingAs($this->person)->postJson('/api/auth/sso/connections', $connection)->assertForbidden();

        $created = $this->actingAs(User::of('admin-1', self::TENANT, administersSso: true))
            ->postJson('/api/auth/sso/connections', $connection)
            ->assertCreated()
            ->assertJsonPath('connection.tenant_id', self::TENANT)
            ->assertJsonPath('connection.enabled', false)
            ->assertJsonPath('connection.secrets.client_secret.set', true);

        $connectionId = self::text($created, 'connection.id');

        self::assertStringNotContainsString('acme-secret', (string) $created->baseResponse->getContent());
        $this->getJson('/api/auth/sso/connections/' . $connectionId)->assertOk()->assertJsonPath('id', $connectionId);
        $this->actingAs(User::of('admin-2', 'tenant-2', administersSso: true))->getJson('/api/auth/sso/connections/' . $connectionId)->assertNotFound();
    }

    /**
     * An administrator claims a domain and verifies it once it is published.
     *
     * @return void
     */
    public function testClaimingAndVerifyingADomain(): void
    {
        $this->actingAs(User::of('admin-1', self::TENANT, administersSso: true));

        $domains = '/api/auth/sso/connections/' . $this->connectionId . '/domains';
        $claimed = $this->postJson($domains, ['domain' => 'Example.COM'])->assertCreated()->assertJsonPath('record.name', '_sso-verification.example.com');

        $this->dns->found('_sso-verification.example.com', self::text($claimed, 'record.value'));

        $this->postJson($domains . '/example.com/verifications')->assertOk()->assertJsonPath('status', 'verified');
        $this->postJson($domains . '/other.example.com/verifications')->assertNotFound();
    }

    /**
     * Only the assertion consumer service is exempt from CSRF verification.
     *
     * @return void
     */
    public function testOnlyTheAssertionConsumerServiceIsExemptFromCsrf(): void
    {
        if (!(new \ReflectionClass(Middleware::class))->hasMethod('preventRequestForgery')) {
            self::markTestSkipped('This Laravel names it validateCsrfTokens(), which takes the same except list.');
        }

        $middleware = new Middleware;

        // @snippet-start route-csrf
        // In bootstrap/app.php, inside the withMiddleware() callback
        $middleware->preventRequestForgery(except: ['api/auth/sso/connections/*/assertions']);
        // @snippet-end route-csrf
        $except   = $this->csrfExemptions($middleware);
        $verifier = new class ($except) {
            use ExcludesPaths;

            /**
             * Exempt the paths given.
             *
             * @param  list<string>  $except
             */
            public function __construct(

                /** The paths exempt from verification. */
                protected array $except,
            ) {}

            /**
             * Whether Laravel's CSRF middleware would exempt the request.
             *
             * @param  \Illuminate\Http\Request  $request
             * @return bool
             */
            public function exempts(Request $request): bool
            {
                return $this->inExceptArray($request);
            }
        };

        self::assertSame(['api/auth/sso/connections/*/assertions'], $except);
        self::assertTrue($verifier->exempts(Request::create('/api/auth/sso/connections/' . $this->connectionId . '/assertions', 'POST')));

        $guarded = ['/auth/sessions', '/auth/sso/links', '/auth/sso/reauthentications', '/auth/sso/connections', '/auth/sso/connections/' . $this->connectionId . '/domains'];

        foreach ($guarded as $path) {
            self::assertFalse($verifier->exempts(Request::create('/api' . $path, 'POST')), $path);
        }
    }

    /**
     * The paths the `web` group's CSRF middleware exempts.
     *
     * @param  \Illuminate\Foundation\Configuration\Middleware  $middleware
     * @return list<string>
     */
    private function csrfExemptions(Middleware $middleware): array
    {
        $verifiers = array_values(array_filter(
            $middleware->getMiddlewareGroups()['web'],
            static fn (mixed $class): bool => is_string($class) && method_exists($class, 'getExcludedPaths'),
        ));

        self::assertCount(1, $verifiers, 'The web group has one CSRF middleware.');

        $verifier = $this->app?->make($verifiers[0]);
        $except   = is_object($verifier) && method_exists($verifier, 'getExcludedPaths') ? $verifier->getExcludedPaths() : null;

        self::assertIsArray($except);

        return array_values(array_filter($except, is_string(...)));
    }

    /**
     * Link the person through the link routes and answer the link's id.
     *
     * @return string
     */
    private function linkOverHttp(): string
    {
        $this->actingAs($this->person);

        $start  = $this->startOverHttp('/api/auth/sso/links/authorization-requests');
        $linked = $this->postJson('/api/auth/sso/links', $this->redemptionOf($this->completeOverHttp($start), $start))->assertCreated();

        return self::text($linked, 'link');
    }

    /**
     * Start a flow at the route, through the SAML connection by default.
     *
     * @param  string  $uri
     * @param  array<string, string>  $body
     * @return array{reference: string, navigation: array<string, mixed>, verifier: string}
     */
    private function startOverHttp(string $uri, array $body = []): array
    {
        $started = $this->postJson($uri, $body + ['application' => self::APPLICATION, 'connection' => $this->connectionId])
            ->assertOk()
            ->assertJsonStructure(['reference', 'navigation' => ['type', 'url'], 'verifier']);

        /** @var array{reference: string, navigation: array<string, mixed>, verifier: string} */
        return $started->json();
    }

    /**
     * Post the identity provider's response to the ACS route and read the
     * redirect.
     *
     * @param  array{reference: string, navigation: array<string, mixed>, verifier: string}  $start
     * @return \SineMacula\Laravel\Sso\Testing\HandoffRedirect
     */
    private function completeOverHttp(array $start): HandoffRedirect
    {
        $request  = $this->idp->receive($start['navigation']);
        $response = $this->idp->respondTo($request, $this->clock->now());
        $redirect = $this->redirectOf($this->post('/api/auth/sso/connections/' . $this->connectionId . '/assertions', $response->post($request->relayState)), 303);

        self::assertSame($start['reference'], $redirect->reference);

        return $redirect;
    }

    /**
     * The redirect a completion route answered with the status given.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @param  int  $status
     * @return \SineMacula\Laravel\Sso\Testing\HandoffRedirect
     */
    private function redirectOf(TestResponse $response, int $status): HandoffRedirect
    {
        $response->assertStatus($status);

        return HandoffRedirect::from($response->headers->get('Location'));
    }

    /**
     * The body the client posts to redeem the redirect's code.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\HandoffRedirect  $redirect
     * @param  array{reference: string, navigation: array<string, mixed>, verifier: string}  $start
     * @return array{application: string, connection: string, code: string, verifier: string}
     */
    private function redemptionOf(HandoffRedirect $redirect, array $start): array
    {
        return ['application' => self::APPLICATION, 'connection' => $this->connectionId, 'code' => $redirect->code(), 'verifier' => $start['verifier']];
    }

    /**
     * The string the response's JSON holds at the key.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @param  string  $key
     * @return string
     */
    private static function text(TestResponse $response, string $key): string
    {
        $value = $response->json($key);

        return is_string($value) ? $value : self::fail("The response holds no string at [{$key}].");
    }

    /**
     * The URL a started flow navigates to.
     *
     * @param  array{reference: string, navigation: array<string, mixed>, verifier: string}  $start
     * @return string
     */
    private static function navigationUrl(array $start): string
    {
        return is_string($start['navigation']['url'] ?? null) ? $start['navigation']['url'] : self::fail('The start has no navigation URL.');
    }
}
