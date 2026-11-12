<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Configuration;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\ApplicationGate;
use SineMacula\Laravel\Sso\Applications\ApplicationRegistry;
use SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Config\ConfigurationChecks;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * Examples of `docs/guides/configuration.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionEndpoints::class)]
#[CoversClass(Application::class)]
#[CoversClass(ApplicationRegistry::class)]
#[CoversClass(ApplicationGate::class)]
#[CoversClass(ConfigurationChecks::class)]
final class ConfigurationExampleTest extends ExampleTestCase
{
    /** @var string The tenant of the second client. */
    private const string OTHER_TENANT = 'tenant-2';

    /** @var string The issuer of the second client's OpenID provider. */
    private const string OTHER_ISSUER = 'https://other-op.example.test';

    /** @var string Where the native application's handoff goes. */
    private const string MOBILE_REDIRECT_URI = 'com.example.app:/auth/sso/complete';

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /**
     * Configure each client's host and make the person.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('clients.hosts', [self::TENANT => 'acme.app.example.com', self::OTHER_TENANT => 'globex.app.example.com']);

        $this->person = new IdentityReference('App\Models\User', 'person-1');
    }

    /**
     * An OIDC flow uses the connection's own callback as its `redirect_uri`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheApplicationsEndpointsCarryAnOidcFlow(): void
    {
        app()->register(AppServiceProvider::class);

        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);
        $start        = $this->startFlow(Purpose::LINK, $connectionId, $this->person);

        parse_str((string) parse_url($start->navigation?->url() ?? '', PHP_URL_QUERY), $query);

        self::assertSame("https://sso.example.com/{$connectionId}/callback", $query['redirect_uri'] ?? null);

        $redirect = $this->respondAtProvider($provider, $connectionId, $start);

        self::assertTrue($this->redeemLink($connectionId, $redirect, $start, $this->person)->isRedeemed());
    }

    /**
     * A SAML flow uses the connection's own endpoints and refuses a response
     * addressed to the default ones.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheApplicationsEndpointsCarryASamlFlowAndOnlyThem(): void
    {
        app()->register(AppServiceProvider::class);

        $idp          = new FakeSamlIdentityProvider;
        $connectionId = $this->makeSamlConnection($idp);
        $start        = $this->startFlow(Purpose::LINK, $connectionId, $this->person);
        $request      = $idp->receive($start);

        self::assertSame("https://sso.example.com/{$connectionId}/acs", $request->assertionConsumerService);
        self::assertSame("https://sso.example.com/{$connectionId}/metadata", $request->issuer);
        self::assertTrue($this->respondAtProvider($idp, $connectionId, $start)->hasCode());

        $default = "https://sp.example.test/auth/sso/connections/{$connectionId}/assertions";
        $start   = $this->startFlow(Purpose::LINK, $connectionId, $this->person);
        $refused = $this->respondAtProvider($idp, $connectionId, $start, static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with(['destination' => $default]));

        self::assertSame(FailureReason::RECIPIENT_MISMATCH->value, $refused->error);
    }

    /**
     * Rows of `[an endpoint that is not an exact web URL]`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideEndpointsRefused(): iterable
    {
        yield 'plain http' => ['http://sso.example.com/acs'];
        yield 'relative' => ['/acs'];
        yield 'user information' => ['https://admin@sso.example.com/acs'];
        yield 'fragment' => ['https://sso.example.com/acs#here'];
        yield 'wildcard' => ['https://*.example.com/acs'];
    }

    /**
     * Connection endpoints must be absolute `https` URLs, or `http` on
     * loopback, with no user information, fragment or wildcard.
     *
     * @param  string  $url
     * @return void
     */
    #[DataProvider('provideEndpointsRefused')]
    public function testConnectionEndpointsRefuseAnythingButAnExactWebUrl(string $url): void
    {
        $loopback = new ConnectionEndpoints('http://127.0.0.1/acs', 'http://127.0.0.1/callback', 'http://127.0.0.1/metadata', 'http://127.0.0.1/metadata', 'http://[::1]/jwks');

        self::assertSame('http://[::1]/jwks', $loopback->jwks);

        $this->expectExceptionObject(new \InvalidArgumentException(
            '`endpoints.assertion_consumer_service` must be an absolute https URL (or http on 127.0.0.1 or [::1]) with no user information, fragment or wildcard.',
        ));

        new ConnectionEndpoints($url, 'https://sso.example.com/callback', 'https://sso.example.com/metadata', 'https://sso.example.com/metadata', 'https://sso.example.com/jwks');
    }

    /**
     * The published configuration registers both applications, defaulting what
     * it leaves out.
     *
     * @return void
     */
    public function testThePublishedConfigurationRegistersBothApplications(): void
    {
        $this->publishConfiguration();

        $registry = app(ApplicationRegistry::class);
        $mobile   = $registry->find('mobile');
        $web      = $registry->find('web');

        self::assertSame(['web', 'mobile'], array_keys($registry->all()));
        self::assertNull($registry->find('Mobile'));

        self::assertNotNull($mobile);
        self::assertSame(self::MOBILE_REDIRECT_URI, $mobile->redirectUri);
        self::assertTrue($mobile->externalSignIn);
        self::assertSame(HandoffDelivery::FRAGMENT, $mobile->delivery);
        self::assertTrue($mobile->discoveryEnabled);
        self::assertSame('com.example.app:/sign-in', $mobile->discoveryFallbackUrl);
        self::assertFalse($mobile->unlinkedHandoffs);
        self::assertSame(60, $mobile->handoffTtlSeconds);

        self::assertNotNull($web);
        self::assertSame('https://app.example.com/auth/sso/complete', $web->redirectUri);
        self::assertSame(HandoffDelivery::FRAGMENT, $web->delivery);
        self::assertFalse($web->discoveryEnabled);
        self::assertNull($web->discoveryFallbackUrl);
        self::assertFalse($web->unlinkedHandoffs);
        self::assertSame(60, $web->handoffTtlSeconds);
    }

    /**
     * The native application's code arrives in the fragment and lasts its sixty
     * seconds.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheNativeApplicationsCodeLastsItsLifetime(): void
    {
        $this->publishConfiguration();

        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);
        $redemption   = app(HandoffRedemption::class);

        $start    = $this->startMobile(Purpose::LINK, $connectionId, $this->person);
        $location = $this->completeAt($provider, $connectionId, $start);

        self::assertSame(self::MOBILE_REDIRECT_URI, Str::before($location, '#'));
        self::assertStringStartsWith(self::MOBILE_REDIRECT_URI . '#code=', $location);

        $this->clock->advance(59);

        $redeemed = $redemption->redeem(
            Purpose::LINK,
            'mobile',
            $connectionId,
            HandoffRedirect::from($location)->code(),
            self::verifierOf($start),
            Clients::browser(),
            new Caller($this->person),
        );

        self::assertTrue($redeemed->isRedeemed());

        $start    = $this->startMobile(Purpose::LINK, $connectionId, $this->person);
        $redirect = HandoffRedirect::from($this->completeAt($provider, $connectionId, $start));

        $this->clock->advance(60);

        $expired = $redemption->redeem(Purpose::LINK, 'mobile', $connectionId, $redirect->code(), self::verifierOf($start), Clients::browser(), new Caller($this->person));

        self::assertTrue($expired->isRefused());
        self::assertSame(FailureReason::HANDOFF_EXPIRED, $expired->reason);
    }

    /**
     * The native application is sent `unlinked` with no code for an unlinked
     * sign-in.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheNativeApplicationIsHandedOffNoUnlinkedSignIn(): void
    {
        $this->publishConfiguration();

        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);
        $location     = $this->completeAt($provider, $connectionId, $this->startMobile(Purpose::SIGN_IN, $connectionId));
        $redirect     = HandoffRedirect::from($location);

        self::assertSame(self::MOBILE_REDIRECT_URI, Str::before($location, '#'));
        self::assertFalse($redirect->hasCode());
        self::assertSame(FailureReason::UNLINKED->value, $redirect->error);
    }

    /**
     * Each client's web application is sent to that client's own host.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEachClientIsSentToItsOwnHost(): void
    {
        $this->publishConfiguration();

        app()->register(AppServiceProvider::class);

        $acme   = new FakeOpenIdProvider(clock: $this->clock);
        $globex = new FakeOpenIdProvider(self::OTHER_ISSUER, clock: $this->clock);
        $acmeId = $this->makeOidcConnection($acme);
        $other  = $this->otherTenantsConnection($globex);

        $toAcme   = $this->completeAt($acme, $acmeId, $this->startFlow(Purpose::LINK, $acmeId, $this->person));
        $toGlobex = $this->completeAt($globex, $other, $this->startFlow(Purpose::LINK, $other, $this->person));
        $toMobile = $this->completeAt($acme, $acmeId, $this->startMobile(Purpose::LINK, $acmeId, $this->person));

        self::assertStringStartsWith('https://acme.app.example.com/auth/sso/complete#code=', $toAcme);
        self::assertStringStartsWith('https://globex.app.example.com/auth/sso/complete#code=', $toGlobex);
        self::assertStringStartsWith(self::MOBILE_REDIRECT_URI . '#code=', $toMobile);
    }

    /**
     * A resolver answer that is not an exact redirect URI stops the completion
     * with a `LogicException`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnAnswerThatIsNotAnExactRedirectUriStopsTheCompletion(): void
    {
        $this->publishConfiguration();

        app()->register(AppServiceProvider::class);

        config()->set('clients.hosts', [self::TENANT => '*.app.example.com']);

        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);
        $start        = $this->startFlow(Purpose::LINK, $connectionId, $this->person);

        $this->expectExceptionObject(new \LogicException('The bound redirect URI resolver answered the [web] application with a URI that is not an exact redirect URI.'));

        $this->completeAt($provider, $connectionId, $start);
    }

    /**
     * The application's check runs after the package's and reports a client
     * without a host.
     *
     * @return void
     */
    public function testTheApplicationsOwnCheckRunsWithThePackages(): void
    {
        app()->register(AppServiceProvider::class);

        $report = app(ConfigurationChecker::class)->report();

        self::assertSame('clients', array_key_last($report));
        self::assertSame([], $report['clients']);

        config()->set('clients.hosts', [self::TENANT => 'acme.app.example.com', self::OTHER_TENANT => '']);

        self::assertSame(['`clients.hosts` must give each client a host.'], app(ConfigurationChecker::class)->report()['clients']);
    }

    /**
     * Merge the guide's published configuration over the package's, as Laravel
     * does.
     *
     * @return void
     */
    private function publishConfiguration(): void
    {
        /** @var array<string, mixed> $published */
        $published = require __DIR__ . '/config/sso.php';

        /** @var array<string, mixed> $package */
        $package = config('sso');

        config()->set('sso', array_replace($package, $published));
    }

    /**
     * Start a flow of the native application through the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $connectionId
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    private function startMobile(Purpose $purpose, string $connectionId, ?IdentityReference $identity = null): StartResult
    {
        return app(AuthorizationRequestService::class)->start('mobile', $purpose, $connectionId, Clients::browser(), null, $identity === null ? null : new Caller($identity));
    }

    /**
     * Complete the start at the connection's callback and answer the `Location`
     * the browser is sent to.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function completeAt(FakeOpenIdProvider $provider, string $connectionId, StartResult $start): string
    {
        $result = app(CompletionService::class)->complete(
            CompletionEndpoint::CALLBACK,
            $connectionId,
            new CompletionRequest('GET', $provider->authorize($start)->query(), []),
            Clients::browser(),
        );
        $location = app(CompletionResponses::class)->from($result, 'GET')->location();

        self::assertNotNull($location);

        return $location;
    }

    /**
     * An enabled OIDC connection of the second client's tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @return string
     */
    private function otherTenantsConnection(FakeOpenIdProvider $provider): string
    {
        $provider->serve($this->fetcher);

        $connections = app(ConnectionService::class);
        $created     = $connections->create(self::OTHER_TENANT, 'oidc', 'Other OIDC', Clients::browser(), [
            'issuer'                 => $provider->issuer,
            'authorization_endpoint' => $provider->endpoint('authorization'),
            'token_endpoint'         => $provider->endpoint('token'),
            'jwks_uri'               => $provider->endpoint('jwks'),
            'client_id'              => FakeOpenIdProvider::CLIENT_ID,
            'client_secret'          => FakeOpenIdProvider::CLIENT_SECRET,
        ]);
        $connectionId = (string) $created->connection?->id;

        self::assertTrue($connections->enable(self::OTHER_TENANT, $connectionId, Clients::browser())->isSucceeded());

        return $connectionId;
    }
}
