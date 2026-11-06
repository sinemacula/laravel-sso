<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\FrozenClock;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use Tests\Integration\Examples\Application\EveryoneMayLink;
use Tests\Integration\Examples\Application\ExampleSessions;
use Tests\TestCase;

/**
 * The shared example harness (SSO-12.4, SSO-12.5): the test case an application
 * would write to test its SSO flows without a network, from which the testing
 * guide's snippets are taken (`docs/guides/testing.md`), and on which every
 * other executable example in the documentation runs.
 *
 * It stands on the package's public API alone. It binds the package's fakes and
 * the application's own contracts, configures both protocols, and has the base
 * class create the package's tables through its shipped migrations, as an
 * application runs them; the steps a client and an identity provider take are
 * its methods, each calling one public helper of the package or one fake.
 * Nothing here, and nothing in an example, uses the package's own test traits
 * or fixtures, reads the package's tables, or builds a verified result by hand:
 * the base class only supplies the database connection the suite runs on and
 * the package's tables, as an application's own `TestCase` does. The flows'
 * helpers refuse to run inside a transaction on the package's storage
 * connection, so an example never wraps itself in one as `RefreshDatabase`
 * does. `tests/Unit/Documentation/ExamplesUsePublicApiTest.php` holds every
 * example to that, and `ExampleSnippetsTest` holds every snippet in the
 * documentation to its source here.
 *
 * Examples call the package's helpers in place of the routes an application
 * adds, since the package adds none: a route only turns a helper's value into a
 * response.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-type IdTokenTailor \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): (\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken|string)
 * @phpstan-type ResponseTailor \Closure(\SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse): \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
 *
 * @internal
 */
abstract class ExampleTestCase extends TestCase
{
    /** @var string The tenant every example connection belongs to. */
    protected const string TENANT = 'tenant-1';

    /** @var string The application every example flow signs into. */
    protected const string APPLICATION = 'web';

    /** @var string Where that application's handoff goes. */
    protected const string REDIRECT_URI = 'https://app.example.com/sso';

    /** @var string The instant the clock is frozen at. */
    protected const string NOW = '2026-11-01T09:30:00Z';

    /** @var \SineMacula\Laravel\Sso\Testing\FrozenClock The clock the package reads. */
    protected FrozenClock $clock;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher What answers every outbound request. */
    protected FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeDnsResolver What answers every DNS lookup. */
    protected FakeDnsResolver $dns;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFreshness Whether the caller authenticated recently enough. */
    protected FakeFreshness $freshness;

    /** @var \Tests\Integration\Examples\Application\ExampleSessions The application's sessions. */
    protected ExampleSessions $sessions;

    /**
     * Bind the fakes and the application's contracts, configure the package,
     * and create its tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        // @snippet-start test-case
        $this->clock     = new FrozenClock('2026-11-01T09:30:00Z');
        $this->fetcher   = new FakeFetcher;
        $this->dns       = new FakeDnsResolver;
        $this->freshness = FakeFreshness::fresh();
        $this->sessions  = new ExampleSessions;

        $this->instance(Clock::class, $this->clock);
        $this->instance(Fetcher::class, $this->fetcher);
        $this->instance(DnsResolver::class, $this->dns);
        $this->instance(Freshness::class, $this->freshness);
        $this->instance(ReauthenticationSessions::class, $this->sessions);
        $this->instance(LinkEligibility::class, new EveryoneMayLink);
        $this->instance(Linker::class, app(LinkStore::class));

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', [
            'web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
        ]);
        // @snippet-end test-case
        $this->usePackageTables();
    }

    /**
     * An enabled SAML connection of the tenant, trusting the provider's
     * certificate, with any settings given laid over the provider's own.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider  $idp
     * @param  array<string, mixed>  $settings
     * @return string
     */
    protected function makeSamlConnection(FakeSamlIdentityProvider $idp, array $settings = []): string
    {
        // @snippet-start saml-connection
        $created = app(ConnectionService::class)->create(self::TENANT, 'saml2', 'Example SAML', [
            'idp_entity_id' => $idp->entityId,
            'sso_url'       => FakeSamlIdentityProvider::SSO_URL,
            ...$settings,
        ]);

        $connectionId = (string) $created->connection?->id;

        static::assertTrue(app(KeyService::class)->trustCertificate(self::TENANT, $connectionId, $idp->certificate())->isSucceeded());
        // @snippet-end saml-connection
        return $this->enabled($created);
    }

    /**
     * An enabled OIDC connection of the tenant, its provider answering on the
     * fake fetcher, with any settings given laid over the provider's own.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @param  array<string, mixed>  $settings
     * @return string
     */
    protected function makeOidcConnection(FakeOpenIdProvider $provider, array $settings = []): string
    {
        // @snippet-start oidc-connection
        $provider->serve($this->fetcher);

        $created = app(ConnectionService::class)->create(self::TENANT, 'oidc', 'Example OIDC', [
            'issuer'                 => $provider->issuer,
            'authorization_endpoint' => $provider->endpoint('authorization'),
            'token_endpoint'         => $provider->endpoint('token'),
            'jwks_uri'               => $provider->endpoint('jwks'),
            'client_id'              => FakeOpenIdProvider::CLIENT_ID,
            'client_secret'          => FakeOpenIdProvider::CLIENT_SECRET,
            ...$settings,
        ]);
        // @snippet-end oidc-connection
        return $this->enabled($created);
    }

    /**
     * Start a flow of the application through the connection, as the start
     * route does, with no challenge from the client: the package generates the
     * verifier, which the started answer carries once.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $connectionId
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    protected function startFlow(Purpose $purpose, string $connectionId, ?IdentityReference $identity = null, ?string $sessionId = null): StartResult
    {
        return app(AuthorizationRequestService::class)->start(self::APPLICATION, $purpose, $connectionId, null, $identity, $sessionId);
    }

    /**
     * Have the provider answer the start, deliver its answer to the
     * connection's completion endpoint, and read the redirect the browser is
     * sent back with, as the client does; a tailor changes the SAML response or
     * the ID token.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider|\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider  $provider
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  IdTokenTailor|ResponseTailor|null  $tailor
     * @return \SineMacula\Laravel\Sso\Testing\HandoffRedirect
     *
     * @throws \Random\RandomException
     */
    protected function respondAtProvider(FakeOpenIdProvider|FakeSamlIdentityProvider $provider, string $connectionId, StartResult $start, ?\Closure $tailor = null): HandoffRedirect
    {
        if ($provider instanceof FakeOpenIdProvider) {

            /** @var ?IdTokenTailor $tailor */
            $grant  = $provider->authorize($start, $tailor);
            $result = app(CompletionService::class)->callback($connectionId, new CompletionRequest('GET', $grant->query(), []));

            return HandoffRedirect::from(app(CompletionResponses::class)->from($result, 'GET'));
        }

        $request  = $provider->receive($start);
        $response = $provider->respondTo($request, $this->clock->now());

        /** @var ?ResponseTailor $tailor */
        $response = $tailor === null ? $response : $tailor($response);
        $result   = app(CompletionService::class)->assertionConsumerService($connectionId, $response->completionRequest($request->relayState));

        return HandoffRedirect::from(app(CompletionResponses::class)->from($result, 'POST'));
    }

    /**
     * Redeem a `link` code alone, as the caller the application has
     * authenticated: a `link` writes no session, so it needs no transaction of
     * the application's.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Testing\HandoffRedirect  $redirect
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    protected function redeemLink(string $connectionId, HandoffRedirect $redirect, StartResult $start, IdentityReference $caller): RedemptionResult
    {
        // @snippet-start redeem-link
        return app(HandoffRedemption::class)->redeem(Purpose::LINK, self::APPLICATION, $connectionId, $redirect->code(), self::verifierOf($start), $caller);
        // @snippet-end redeem-link
    }

    /**
     * Admit a `sign_in` code in the application's transaction on the package's
     * storage connection, writing the session it establishes in that same
     * transaction, as a sign-in endpoint does.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Testing\HandoffRedirect  $redirect
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  string  $sessionId
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    protected function admitSignIn(string $connectionId, HandoffRedirect $redirect, StartResult $start, string $sessionId): RedemptionResult
    {
        // @snippet-start admit-sign-in
        return DB::connection(StorageConnection::name())->transaction(function () use ($connectionId, $redirect, $start, $sessionId): RedemptionResult {

            $result = app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, self::APPLICATION, $connectionId, $redirect->code(), self::verifierOf($start));

            if ($result->isRedeemed() && $result->linkedIdentity !== null) {
                // As fresh as the provider says, or now when it said nothing
                $authenticatedAt = $result->result?->authenticationContext->authenticatedAt ?? $this->clock->now();

                $this->sessions->establish($sessionId, $result->linkedIdentity, self::APPLICATION, $connectionId, (string) $result->linkId, $authenticatedAt);
            }

            return $result;
        });
        // @snippet-end admit-sign-in
    }

    /**
     * Admit a `reauthenticate` code in the application's transaction, in which
     * the package renews the session the code is bound to.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Testing\HandoffRedirect  $redirect
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    protected function admitReauthentication(string $connectionId, HandoffRedirect $redirect, StartResult $start): RedemptionResult
    {
        $code     = $redirect->code();
        $verifier = self::verifierOf($start);

        return DB::connection(StorageConnection::name())->transaction(
            static fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::REAUTHENTICATE, self::APPLICATION, $connectionId, $code, $verifier),
        );
    }

    /**
     * Link the identity through a whole `link` flow at the provider.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider|\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider  $provider
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Random\RandomException
     */
    protected function linkThroughFlow(FakeOpenIdProvider|FakeSamlIdentityProvider $provider, string $connectionId, IdentityReference $identity): RedemptionResult
    {
        $start  = $this->startFlow(Purpose::LINK, $connectionId, $identity);
        $linked = $this->redeemLink($connectionId, $this->respondAtProvider($provider, $connectionId, $start), $start, $identity);

        static::assertTrue($linked->isRedeemed());

        return $linked;
    }

    /**
     * Sign in through a whole `sign_in` flow at the provider, establishing the
     * session.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider|\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider  $provider
     * @param  string  $connectionId
     * @param  string  $sessionId
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Random\RandomException
     */
    protected function signInThroughFlow(FakeOpenIdProvider|FakeSamlIdentityProvider $provider, string $connectionId, string $sessionId): RedemptionResult
    {
        $start = $this->startFlow(Purpose::SIGN_IN, $connectionId);

        return $this->admitSignIn($connectionId, $this->respondAtProvider($provider, $connectionId, $start), $start, $sessionId);
    }

    /**
     * The verifier the started flow's client keeps: the package generated it,
     * since the client sent no challenge.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return string
     */
    protected static function verifierOf(StartResult $start): string
    {
        return $start->verifier?->reveal() ?? static::fail('The flow did not start, so the client holds no verifier.');
    }

    /**
     * Enable the connection just created, and answer its id once it is usable.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionResult  $created
     * @return string
     */
    private function enabled(ConnectionResult $created): string
    {
        $connectionId = (string) $created->connection?->id;
        $connections  = app(ConnectionService::class);

        static::assertTrue($connections->enable(self::TENANT, $connectionId)->isSucceeded());
        static::assertTrue($connections->get(self::TENANT, $connectionId)?->usable);

        return $connectionId;
    }
}
