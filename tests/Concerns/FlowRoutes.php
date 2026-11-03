<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Discovery\DiscoveryService;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Responses\CompletionResponse;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Linking\RecordingSessions;

/**
 * What the operational acceptance tests stand on: the routes an application
 * would add, none in a middleware group, each calling one public helper of the
 * package, since the package adds no route; the contracts a real application
 * binds; connections of real SAML and OIDC providers, each a tenant of its own;
 * and a client for the routes, which holds what a browser or a client holds and
 * nothing else. A test decides how a request reaches the routes
 * (`sendFlowRequest()`): the HTTP kernel, unless it serves them through a
 * long-lived worker.
 *
 * Contracts the provider binds as scoped are given through a closure and never
 * through `instance()`: a worker forgets every scoped instance after each
 * request or job, and would then answer the default.
 *
 * The fetcher is a wrapper of the fake. A worker test asks what the root
 * application retains of a flow, and the fake, a package object, records every
 * request it answers for the test to read; the wrapper keeps that outside the
 * walk, and runs what a test arms just before the token request, which is after
 * the request's consumption and before the completion's locked transaction.
 *
 * Every value is the full width of its column, so a test runs on PostgreSQL and
 * MySQL as on SQLite.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait FlowRoutes
{
    use UsesConnections, UsesDomains, UsesEnforcement, UsesEveryTable, UsesFlowTables;

    /** @var string The application that signs people in. */
    protected const string FLOW_APPLICATION = 'web';

    /** @var string The application that offers discovery. */
    protected const string DISCOVERING_APPLICATION = 'discovering';

    /** @var string Where each application's handoff goes. */
    protected const string FLOW_REDIRECT_URI = 'https://app.example.com/sso';

    /** @var string Where a discovery miss leads. */
    protected const string FLOW_FALLBACK_URL = 'https://app.example.com/sign-in';

    /** @var string Where an IdP-initiated response is sent to start again. */
    protected const string FLOW_START_URL = 'https://app.example.com/sso/start';

    /** @var string The instant the flow clock starts at. */
    protected const string FLOW_NOW = '2026-11-01T09:30:00Z';

    /** @var string The `kid` every provider's first key signs under. */
    protected const string SHARED_KID = 'shared-kid';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    protected FixedClock $flowClock;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fake every provider answers on. */
    protected FakeFetcher $flowFetcher;

    /** @var \Tests\Fixtures\Linking\RecordingSessions The session contract of a `reauthenticate`. */
    protected RecordingSessions $flowSessions;

    /** @var ?\Closure(): void What runs once, just before the next token request. */
    protected ?\Closure $beforeTokenRequest = null;

    /** @var array<string, \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey> The signing keys made, by name. */
    private static array $flowKeys = [];

    /** @var array<string, \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider> The SAML providers made, by host. */
    private static array $flowIdps = [];

    /** @var array<string, \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider> The OIDC provider of each connection, by its id. */
    private array $flowProviders = [];

    /** @var array<string, \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider> The SAML provider of each connection, by its id. */
    private array $flowIdpOf = [];

    /**
     * Send the request to the routes, through the HTTP kernel. A test that
     * serves them through a long-lived worker declares its own.
     *
     * @param  string  $method
     * @param  string  $uri
     * @param  array<string, mixed>  $parameters
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    protected function sendFlowRequest(string $method, string $uri, array $parameters = []): TestResponse
    {
        return $this->call($method, $uri, $parameters, [], [], ['HTTP_ACCEPT' => 'application/json', 'REMOTE_ADDR' => '203.0.113.7']);
    }

    /**
     * Bind the clock, the fetcher and the contracts of a real application, and
     * configure both protocols, discovery, IdP-initiated sign-in, the
     * endpoints, the applications and limits no test reaches by accident.
     *
     * @return void
     */
    protected function prepareFlows(): void
    {
        $this->flowClock    = new FixedClock(self::FLOW_NOW);
        $this->flowFetcher  = new FakeFetcher;
        $this->flowSessions = new RecordingSessions;

        $fetcher = $this->wrappedFetcher();

        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $app->instance(Clock::class, $this->flowClock);
        $app->instance(Freshness::class, FakeFreshness::fresh());
        $app->instance(ReauthenticationSessions::class, $this->flowSessions);
        $app->instance(LinkEligibility::class, new AllowingLinkEligibility);
        $app->bind(Fetcher::class, static fn (): Fetcher => $fetcher);
        $app->scoped(Linker::class, LinkStore::class);

        config()->set('app.debug', false);
        config()->set('sso.features.saml2', true);
        config()->set('sso.features.oidc', true);
        config()->set('sso.features.discovery', true);
        config()->set('sso.features.idp_initiated', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.discovery.minimum_duration_milliseconds', 50);
        config()->set('sso.applications', [
            self::FLOW_APPLICATION        => ['redirect_uri' => self::FLOW_REDIRECT_URI, 'external_sign_in' => true, 'unlinked_handoffs' => true],
            self::DISCOVERING_APPLICATION => [
                'redirect_uri'      => self::FLOW_REDIRECT_URI,
                'external_sign_in'  => true,
                'unlinked_handoffs' => true,
                'discovery'         => ['enabled' => true, 'fallback_url' => self::FLOW_FALLBACK_URL],
            ],
        ]);

        $this->raiseFlowLimits();
    }

    /**
     * Set each limit, high enough for a test to count its own: a test that
     * names the counters' connection in its environment leaves the package's
     * limits to be given here.
     *
     * @return void
     */
    protected function raiseFlowLimits(): void
    {
        $limit = ['max' => 100000, 'decay_seconds' => 60];

        config()->set('sso.rate_limits.authorization_request', ['per_ip' => $limit, 'per_email_domain' => $limit]);
        config()->set('sso.rate_limits.completion', ['per_ip' => $limit, 'per_connection' => $limit]);
        config()->set('sso.rate_limits.redemption', ['per_ip' => $limit]);
        config()->set('sso.rate_limits.metadata', ['per_connection' => $limit]);
        config()->set('sso.rate_limits.domain_check', ['per_connection' => $limit]);
    }

    /**
     * The routes an application adds for every flow, in no middleware group.
     *
     * @return void
     */
    protected function registerFlowRoutes(): void
    {
        Route::post('/sso/start/{connection}', static fn (Request $request, string $connection): JsonResponse => self::startAnswer($request, $connection));
        Route::post('/sso/discover', static fn (Request $request): JsonResponse => self::discoveryAnswer($request));
        Route::post('/sso/acs/{connection}', static fn (Request $request, string $connection): CompletionResponse => self::completionAnswer('POST', $request, $connection));
        Route::get('/sso/callback/{connection}', static fn (Request $request, string $connection): CompletionResponse => self::completionAnswer('GET', $request, $connection));
        Route::post('/sso/redeem/{connection}', static fn (Request $request, string $connection): JsonResponse => self::redemptionAnswer($request, $connection));
        Route::get('/sso/metadata/{tenant}/{connection}', static fn (string $tenant, string $connection): Response => self::metadataAnswer($tenant, $connection));
        Route::get('/sso/jwks/{connection}', static fn (string $connection): Response => self::documentAnswer(app(ServiceProviderDescriptions::class)->publicKeys($connection)));
    }

    /**
     * An enabled OIDC connection of a provider of its own, under the tenant and
     * at the host, storing the key the provider signs with.
     *
     * @param  string  $tenant
     * @param  string  $host
     * @param  ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $key
     * @param  string  $algorithm
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    protected function flowOidcConnection(string $tenant, string $host, ?FakeSigningKey $key = null, string $algorithm = 'RS256', array $settings = []): Connection
    {
        $key ??= self::flowKey($host);

        $client   = "client-{$host}";
        $secret   = "secret-{$host}";
        $provider = (new FakeOpenIdProvider("https://{$host}.example.test", $key, $this->flowClock))
            ->signWith($key, $algorithm)
            ->register($client, 'client_secret_basic', $secret)
            ->serve($this->flowFetcher);
        $jwks = (string) json_encode(['keys' => [$key->jwk()]]);

        $connection = $this->makeConnection([
            'tenant_id' => $tenant,
            'enabled'   => true,
            'jwks'      => ProviderKeySet::read($jwks, AlgorithmAllowList::of(['RS256', 'PS256']), 65536, 50)?->toStored(),
            'secrets'   => app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret($secret)]),
            'settings'  => [
                'issuer'                 => $provider->issuer,
                'authorization_endpoint' => $provider->endpoint('authorization'),
                'token_endpoint'         => $provider->endpoint('token'),
                'jwks_uri'               => $provider->endpoint('jwks'),
                'client_id'              => $client,
                'id_token_algorithms'    => [$algorithm],
                ...$settings,
            ],
        ]);

        $this->flowProviders[$connection->id] = $provider;

        return $connection;
    }

    /**
     * An enabled SAML connection trusting a provider of its own, at the host,
     * under the tenant.
     *
     * @param  string  $tenant
     * @param  string  $host
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    protected function flowSamlConnection(string $tenant, string $host, array $settings = []): Connection
    {
        $idp = self::flowIdp($host);

        $connection = $this->makeConnection([
            'tenant_id' => $tenant,
            'protocol'  => 'saml2',
            'enabled'   => true,
            'settings'  => [
                'idp_entity_id' => $idp->entityId,
                'sso_url'       => "https://{$host}.example.test/saml/sso",
                'sso_binding'   => 'http_redirect',
                ...$settings,
            ],
            'attribute_mapping' => ['email' => 'email'],
        ]);

        $this->trustFlowCertificate($connection, $idp->certificate());

        $this->flowIdpOf[$connection->id] = $idp;

        return $connection;
    }

    /**
     * Have the connection trust the certificate, answering its row's id.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $certificate
     * @return string
     */
    protected function trustFlowCertificate(Connection $connection, string $certificate): string
    {
        $masked = MaskedKey::fromCertificate($certificate);
        $key    = new ConnectionKey;

        $key->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $masked->certificate,
            'public_key'    => $masked->publicKey,
            'fingerprint'   => $masked->fingerprint,
        ])->save();

        return $key->id;
    }

    /**
     * The verified claim of the domain for the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $domain
     * @return string
     */
    protected function flowVerifiedDomain(Connection $connection, string $domain): string
    {
        return $this->makeDomain($connection, $domain, ['state' => DomainState::VERIFIED])->id;
    }

    /**
     * A signing key made once for the class, by name, under the `kid` given.
     *
     * @param  string  $name
     * @param  string  $kid
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    protected static function flowKey(string $name, string $kid = self::SHARED_KID): FakeSigningKey
    {
        return self::$flowKeys[$name] ??= FakeSigningKey::rsa($kid);
    }

    /**
     * A SAML provider made once for the class, by the host it stands at.
     *
     * @param  string  $host
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    protected static function flowIdp(string $host): FakeSamlIdentityProvider
    {
        return self::$flowIdps[$host] ??= new FakeSamlIdentityProvider("https://{$host}.example.test/saml");
    }

    /**
     * The OIDC provider of the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider
     */
    protected function flowProvider(Connection $connection): FakeOpenIdProvider
    {
        return $this->flowProviders[$connection->id];
    }

    /**
     * Ask to start a flow through the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $session
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    protected function flowStart(Connection $connection, string $purpose = 'sign_in', ?IdentityReference $identity = null, ?string $session = null): TestResponse
    {
        return $this->sendFlowRequest('POST', "/sso/start/{$connection->id}", array_filter([
            'purpose'       => $purpose,
            'identity_type' => $identity?->type,
            'identity_id'   => $identity?->id,
            'session'       => $session,
        ], is_string(...)));
    }

    /**
     * Start a flow through the connection, and answer what the client holds of
     * it: its reference, its verifier and where the browser goes.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $session
     * @return array{reference: string, verifier: string, navigation: array{type: string, url: string}}
     */
    protected function startedFlow(Connection $connection, string $purpose = 'sign_in', ?IdentityReference $identity = null, ?string $session = null): array
    {
        $response = $this->flowStart($connection, $purpose, $identity, $session)->assertOk();

        /** @var array{reference: string, verifier: string, navigation: array{type: string, url: string}} */
        return $response->json();
    }

    /**
     * Have the provider answer the start, and send the browser back with its
     * answer: a tailor changes the ID token or the SAML response.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  array{navigation: array{url: string}}  $start
     * @param  ?\Closure  $tailor
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    protected function completeFlow(Connection $connection, array $start, ?\Closure $tailor = null): TestResponse
    {
        if ($connection->protocol !== 'saml2') {
            return $this->deliverGrant($connection, $this->flowGrant($connection, $start, $tailor));
        }

        $response = $this->flowSamlResponse($connection)->inResponseTo(self::samlRequestIdOf($start));

        return $this->postSamlResponse($connection, $tailor === null ? $response : $tailor($response), self::relayStateOf($start));
    }

    /**
     * What the connection's OIDC provider grants the start.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  array{navigation: array{url: string}}  $start
     * @param  ?\Closure  $tailor
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization
     *
     * @throws \Random\RandomException
     */
    protected function flowGrant(Connection $connection, array $start, ?\Closure $tailor = null): FakeAuthorization
    {
        return $this->flowProviders[$connection->id]->authorize($start['navigation']['url'], $tailor);
    }

    /**
     * Send the browser to the connection's callback with what was granted.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization  $grant
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    protected function deliverGrant(Connection $connection, FakeAuthorization $grant): TestResponse
    {
        return $this->sendFlowRequest('GET', "/sso/callback/{$connection->id}?{$grant->query()}");
    }

    /**
     * A response of the connection's SAML provider, made now for its service
     * provider, unsolicited until told what it answers.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    protected function flowSamlResponse(Connection $connection): FakeSamlResponse
    {
        $endpoints = app(EndpointResolver::class)->endpoints($connection);

        return $this->flowIdpOf[$connection->id]->response($endpoints->entityId, $endpoints->assertionConsumerService, $this->flowClock->now());
    }

    /**
     * Post the response to the connection's assertion consumer service.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse  $response
     * @param  ?string  $relayState
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    protected function postSamlResponse(Connection $connection, FakeSamlResponse $response, ?string $relayState = null): TestResponse
    {
        return $this->sendFlowRequest('POST', "/sso/acs/{$connection->id}", $response->post($relayState));
    }

    /**
     * Redeem the code at the connection's redemption endpoint.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $purpose
     * @param  string  $code
     * @param  string  $verifier
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @param  string  $application
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    protected function flowRedeem(
        Connection $connection,
        string $purpose,
        string $code,
        string $verifier,
        ?IdentityReference $caller = null,
        string $application = self::FLOW_APPLICATION,
    ): TestResponse {
        return $this->sendFlowRequest('POST', "/sso/redeem/{$connection->id}", array_filter([
            'purpose'     => $purpose,
            'application' => $application,
            'code'        => $code,
            'verifier'    => $verifier,
            'caller_type' => $caller?->type,
            'caller_id'   => $caller?->id,
        ], is_string(...)));
    }

    /**
     * Start, complete and redeem one `sign_in`, answering what the redemption
     * says of the result.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\Closure  $tailor
     * @return array<string, mixed>
     */
    protected function signedIn(Connection $connection, ?\Closure $tailor = null): array
    {
        $start = $this->startedFlow($connection);
        $code  = $this->completedCode($this->completeFlow($connection, $start, $tailor));

        /** @var array<string, mixed> */
        return $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->assertOk()->json();
    }

    /**
     * Link the identity through a `link` flow, answering the link's id.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?\Closure  $tailor
     * @return string
     */
    protected function linkedThroughFlow(Connection $connection, IdentityReference $identity, ?\Closure $tailor = null): string
    {
        $start = $this->startedFlow($connection, 'link', $identity);
        $code  = $this->completedCode($this->completeFlow($connection, $start, $tailor));

        return (string) $this->flowRedeem($connection, 'link', $code, $start['verifier'], $identity)->assertOk()->json('link_id');
    }

    /**
     * Renew the session through a `reauthenticate` flow, answering what the
     * redemption says of the result.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $linkId
     * @param  string  $session
     * @return array<string, mixed>
     */
    protected function reauthenticatedThroughFlow(Connection $connection, IdentityReference $identity, string $linkId, string $session = 'session-1'): array
    {
        $this->flowSessions->boundLink = $linkId;

        $start = $this->startedFlow($connection, 'reauthenticate', $identity, $session);
        $code  = $this->completedCode($this->completeFlow($connection, $start));

        /** @var array<string, mixed> */
        return $this->flowRedeem($connection, 'reauthenticate', $code, $start['verifier'])->assertOk()->json();
    }

    /**
     * The handoff code the completed response carries, once it is a redirect
     * with no error.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @return string
     */
    protected function completedCode(TestResponse $response): string
    {
        $parameters = self::flowRedirect($response);

        self::assertContains($response->getStatusCode(), [CompletionResponse::FOUND, CompletionResponse::SEE_OTHER], (string) $response->getContent());
        self::assertArrayNotHasKey('error', $parameters);
        self::assertIsString($parameters['code'] ?? null);

        return $parameters['code'];
    }

    /**
     * Assert the response is a failure redirect for the reason.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    protected function assertFailedFlow(TestResponse $response, FailureReason $reason): void
    {
        self::assertContains($response->getStatusCode(), [CompletionResponse::FOUND, CompletionResponse::SEE_OTHER], (string) $response->getContent());
        self::assertSame($reason->value, self::flowRedirect($response)['error'] ?? null);
    }

    /**
     * Have the fetcher answer the URL with the document, as a provider's
     * metadata endpoint does.
     *
     * @param  string  $url
     * @param  string  $document
     * @return void
     */
    protected function serveFlowDocument(string $url, string $document): void
    {
        $this->flowFetcher->respond($url, FetchResult::fetched(200, [], $document));
    }

    /**
     * An OIDC provider that publishes its discovery document and keys.
     *
     * @param  string  $issuer
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $key
     * @return \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider
     */
    protected function servedFlowProvider(string $issuer, FakeSigningKey $key): FakeOpenIdProvider
    {
        return (new FakeOpenIdProvider($issuer, $key, $this->flowClock))->serve($this->flowFetcher);
    }

    /**
     * The value when it is a string, and nothing otherwise, for what an answer
     * decoded from JSON holds.
     *
     * @param  mixed  $value
     * @return string
     */
    protected static function flowText(mixed $value): string
    {
        return is_string($value) ? $value : '';
    }

    /**
     * The parameters of the fragment of the response's redirect.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @return array<array-key, mixed>
     */
    protected static function flowRedirect(TestResponse $response): array
    {
        parse_str((string) parse_url((string) $response->baseResponse->headers->get('Location'), PHP_URL_FRAGMENT), $parameters);

        return $parameters;
    }

    /**
     * The `RelayState` the start sends the provider.
     *
     * @param  array{navigation: array{url: string}}  $start
     * @return string
     */
    protected static function relayStateOf(array $start): string
    {
        return (string) self::queryOf($start)['RelayState'];
    }

    /**
     * The `ID` of the `AuthnRequest` the start sends the provider.
     *
     * @param  array{navigation: array{url: string}}  $start
     * @return string
     */
    protected static function samlRequestIdOf(array $start): string
    {
        $request = (string) gzinflate((string) base64_decode((string) self::queryOf($start)['SAMLRequest'], true));

        self::assertSame(1, preg_match('/\sID="([^"]+)"/', $request, $matches));

        return $matches[1];
    }

    /**
     * The query of the URL the start sends the browser to.
     *
     * @param  array{navigation: array{url: string}}  $start
     * @return array<array-key, mixed>
     */
    protected static function queryOf(array $start): array
    {
        parse_str((string) parse_url($start['navigation']['url'], PHP_URL_QUERY), $query);

        return $query;
    }

    /**
     * What the start route answers.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $connection
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function startAnswer(Request $request, string $connection): JsonResponse
    {
        $session = $request->input('session');
        $result  = app(AuthorizationRequestService::class)->start(
            self::FLOW_APPLICATION,
            Purpose::from((string) $request->input('purpose')),
            $connection,
            null,
            self::identityOf($request, 'identity_type', 'identity_id'),
            is_string($session) ? $session : null,
        );

        return self::startedAnswer($result);
    }

    /**
     * What the discovery route answers.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function discoveryAnswer(Request $request): JsonResponse
    {
        return self::startedAnswer(app(DiscoveryService::class)->start(self::DISCOVERING_APPLICATION, Purpose::SIGN_IN, (string) $request->input('email')));
    }

    /**
     * What the metadata route answers.
     *
     * @param  string  $tenant
     * @param  string  $connection
     * @return \Illuminate\Http\Response
     */
    private static function metadataAnswer(string $tenant, string $connection): Response
    {
        return self::documentAnswer(app(ServiceProviderDescriptions::class)->describe($tenant, $connection));
    }

    /**
     * The start's answer as an application's controller sends it.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $result
     * @return \Illuminate\Http\JsonResponse
     */
    private static function startedAnswer(StartResult $result): JsonResponse
    {
        $status = match (true) {
            $result->isStarted()     => 200,
            $result->isRateLimited() => 429,
            default                  => 422,
        };

        return new JsonResponse($result->body(), $status, $result->headers());
    }

    /**
     * What a completion route answers, through the package's response helper.
     *
     * @param  string  $method
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $connection
     * @return \SineMacula\Laravel\Sso\Responses\CompletionResponse
     *
     * @throws \Throwable
     */
    private static function completionAnswer(string $method, Request $request, string $connection): CompletionResponse
    {
        $query      = (string) $request->getQueryString();
        $completion = new CompletionRequest($method, $query, $method === 'POST' ? $request->request->all() : []);
        $service    = app(CompletionService::class);
        $result     = $method === 'POST' ? $service->assertionConsumerService($connection, $completion) : $service->callback($connection, $completion);

        return app(CompletionResponses::class)->from($result, $method);
    }

    /**
     * What the redemption route answers: a `link` standalone, and any other in
     * the transaction that writes the session.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $connection
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function redemptionAnswer(Request $request, string $connection): JsonResponse
    {
        $purpose = Purpose::from((string) $request->input('purpose'));
        $redeem  = static fn (): RedemptionResult => app(HandoffRedemption::class)->redeem(
            $purpose,
            (string) $request->input('application'),
            $connection,
            (string) $request->input('code'),
            (string) $request->input('verifier'),
            self::identityOf($request, 'caller_type', 'caller_id'),
        );

        $answer = $purpose === Purpose::LINK ? $redeem() : DB::connection(StorageConnection::name())->transaction($redeem);

        return new JsonResponse(self::redemptionBody($answer), $answer->isRedeemed() ? 200 : 422);
    }

    /**
     * What the redemption route says of the result.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $answer
     * @return array<string, mixed>
     */
    private static function redemptionBody(RedemptionResult $answer): array
    {
        return [
            'status'              => $answer->status->value,
            'reason'              => $answer->reason?->value,
            'subject'             => $answer->result?->subject,
            'issuer'              => $answer->result?->issuer,
            'tenant'              => $answer->result?->tenantId,
            'connection'          => $answer->result?->connectionId,
            'reference'           => $answer->result?->requestReference->value,
            'linked'              => $answer->linkedIdentity?->jsonSerialize(),
            'link_id'             => $answer->linkId,
            'enforcement_version' => $answer->enforcementVersion,
        ];
    }

    /**
     * A description as an application serves it: its document, or a 404 with
     * why it cannot be given.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription  $description
     * @return \Illuminate\Http\Response
     */
    private static function documentAnswer(ServiceProviderDescription $description): Response
    {
        if (!$description->isAvailable()) {
            return new Response((string) $description->reason?->value, 404, ['Content-Type' => 'text/plain']);
        }

        return new Response((string) $description->body, 200, ['Content-Type' => (string) $description->contentType]);
    }

    /**
     * The identity the two fields of the request name, if any.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $type
     * @param  string  $id
     * @return ?\SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    private static function identityOf(Request $request, string $type, string $id): ?IdentityReference
    {
        $type = $request->input($type);
        $id   = $request->input($id);

        return is_string($type) && is_string($id) ? new IdentityReference($type, $id) : null;
    }

    /**
     * The fetcher the package is given: the fake, behind a wrapper that runs
     * what is armed just before a token request.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\Fetcher
     */
    private function wrappedFetcher(): Fetcher
    {
        $before = function (FetchRequest $request): void {

            if (!str_ends_with($request->url, '/token') || $this->beforeTokenRequest === null) {
                return;
            }

            $armed = $this->beforeTokenRequest;

            $this->beforeTokenRequest = null;

            $armed();
        };

        return new readonly class ($this->flowFetcher, $before) implements Fetcher {
            /**
             * Constructor. The type of what runs first stays open, since the
             * static analysis reads no docblock of an anonymous class in a
             * trait.
             *
             * @param  \SineMacula\Laravel\Sso\Testing\FakeFetcher  $fake
             * @param  mixed  $before
             */
            public function __construct(

                /** What answers every request. */
                private FakeFetcher $fake,

                /** What runs first. */
                private mixed $before,
            ) {}

            /**
             * Run what is armed, and have the fake answer.
             *
             * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
             * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
             */
            #[\Override]
            public function fetch(FetchRequest $request): FetchResult
            {
                if ($this->before instanceof \Closure) {
                    ($this->before)($request);
                }

                return $this->fake->fetch($request);
            }
        };
    }
}
