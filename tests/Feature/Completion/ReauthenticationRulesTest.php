<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Completion\Rules\LinkRules;
use SineMacula\Laravel\Sso\Completion\Rules\ReauthenticationRules;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\Redemption\ReauthenticationBranch;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\AuthorizationUrl;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokens\AuthenticationTimeRules;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Saml2\AuthnRequests;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AuthenticationRules;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * The forced authentication path end to end (SSO-5.10, SSO-6.10, SSO-7.4,
 * SSO-9.5): a flow started through the public service, completed through the
 * public callback or assertion consumer service, and redeemed through
 * `admit()`, in each driver and in a driver registered by the application.
 *
 * A `reauthenticate` forces fresh authentication (`ForceAuthn`, `prompt=login`
 * with `max_age=0`, whatever the connection configures), and requires the
 * provider's authentication time, no earlier than the request's start less the
 * skew and no later than now plus it. A result with none is refused. What
 * reaches the session is the provider's time, exactly.
 *
 * The clock moves ten seconds between the start and the response, so the start
 * and the response's instant are told apart in every row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReauthenticationRules::class)]
#[CoversClass(LinkRules::class)]
#[CoversClass(ReauthenticationBranch::class)]
#[CoversClass(AuthenticationTimeRules::class)]
#[CoversClass(AuthenticationRules::class)]
#[CoversClass(AuthorizationUrl::class)]
#[CoversClass(AuthnRequests::class)]
final class ReauthenticationRulesTest extends LinkingTestCase
{
    /** @var int The clock skew the rows are built for. */
    private const int SKEW = 60;

    /** @var int The seconds between the start and the response. */
    private const int ELAPSED = 10;

    /** @var string The session the flows are started on. */
    private const string SESSION = 'session-1';

    /** @var string How an instant is compared. */
    private const string INSTANT = 'Y-m-d\TH:i:s.u\Z';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's key, made once. */
    private static ?FakeSigningKey $key = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \Tests\Fixtures\Linking\RecordingSessions The session contract, bound to the link a test makes. */
    private RecordingSessions $sessions;

    /**
     * Set the skew, the endpoints and SAML, and bind the session contract.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.clock.skew_seconds', self::SKEW);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.features.saml2', true);

        $this->sessions = new RecordingSessions;

        $this->app?->instance(ReauthenticationSessions::class, $this->sessions);
    }

    /**
     * Rows of `[seconds, reason]`: when the provider says the person
     * authenticated, from the request's start; what the start less the skew,
     * and now plus it, allow.
     *
     * @return iterable<string, array{0: int, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideAuthenticationTimes(): iterable
    {
        yield 'one second past the skew before the start' => [-61, FailureReason::AUTHENTICATION_EXPIRED];
        yield 'at the skew before the start' => [-60, null];
        yield 'within the skew before the start' => [-59, null];
        yield 'at the start' => [0, null];
        yield 'between the start and the response' => [5, null];
        yield 'at the response' => [self::ELAPSED, null];
        yield 'within the skew after now' => [self::ELAPSED + 59, null];
        yield 'at the skew after now' => [self::ELAPSED + 60, null];
        yield 'one second past the skew after now' => [self::ELAPSED + 61, FailureReason::ASSERTION_EXPIRED];
    }

    /**
     * A driver registered by the application is held to the same window by the
     * completion's rules, once its result is verified: refused with no code, or
     * renewing with exactly the provider's time.
     *
     * @param  int  $seconds
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideAuthenticationTimes')]
    public function testARegisteredDriverIsHeldToTheWindow(int $seconds, ?FailureReason $reason): void
    {
        $this->hold(new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT));

        $started = $this->clock->now();

        $this->verifying->claims = $this->claimsAt($started->addSeconds($seconds));

        $start = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        $this->clock->advance(self::ELAPSED);

        $this->assertEnds($this->complete(), $start, $reason, $started->addSeconds($seconds));
    }

    /**
     * Rows of `[skew, seconds, reason]`.
     *
     * @return iterable<string, array{0: int, 1: int, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideOtherSkews(): iterable
    {
        yield 'thirty seconds, at it before the start' => [30, -30, null];
        yield 'thirty seconds, past it before the start' => [30, -31, FailureReason::AUTHENTICATION_EXPIRED];
        yield 'thirty seconds, at it after now' => [30, self::ELAPSED + 30, null];
        yield 'thirty seconds, past it after now' => [30, self::ELAPSED + 31, FailureReason::ASSERTION_EXPIRED];
        yield 'none, at the start' => [0, 0, null];
        yield 'none, a second before the start' => [0, -1, FailureReason::AUTHENTICATION_EXPIRED];
        yield 'none, at now' => [0, self::ELAPSED, null];
        yield 'none, a second after now' => [0, self::ELAPSED + 1, FailureReason::ASSERTION_EXPIRED];
    }

    /**
     * The skew is read as configured, and none is none.
     *
     * @param  int  $skew
     * @param  int  $seconds
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideOtherSkews')]
    public function testTheConfiguredSkewDecides(int $skew, int $seconds, ?FailureReason $reason): void
    {
        config()->set('sso.clock.skew_seconds', $skew);

        $this->hold(new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT));

        $started = $this->clock->now();

        $this->verifying->claims = $this->claimsAt($started->addSeconds($seconds));

        $start = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        $this->clock->advance(self::ELAPSED);

        $this->assertEnds($this->complete(), $start, $reason, $started->addSeconds($seconds));
    }

    /**
     * A driver registered by the application that states no authentication time
     * is refused at completion, with no code, not left to fail at redemption.
     *
     * @return void
     */
    public function testARegisteredDriverStatingNoTimeIsRefusedAtCompletion(): void
    {
        $this->hold(new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT));

        $this->verifying->claims = new VerifiedClaims(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT, null, ['mail' => self::EMAIL], new AuthenticationContext);

        $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        $completion = $this->complete();

        self::assertSame([true, FailureReason::AUTHENTICATION_EXPIRED, null], [$completion->isFailed(), $completion->reason, $completion->handoff]);
        self::assertSame(0, StoredCode::query()->count());
        self::assertSame(0, $this->sessions->renewals());
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::AUTHENTICATION_EXPIRED);
    }

    /**
     * A `sign_in` is held to no such window: it is not a reauthentication, and
     * states what it states.
     *
     * @return void
     */
    public function testASignInIsNotHeldToTheWindow(): void
    {
        $this->hold(new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT));

        $this->verifying->claims = $this->claimsAt($this->clock->now()->subDay());

        $this->start();

        self::assertTrue($this->complete()->isCompleted());
    }

    /**
     * A `link` is held to no such window either: the link rules judge the
     * identity and the subject, and a caller's freshness stands for its own
     * authentication, not the provider's.
     *
     * @return void
     */
    public function testALinkIsNotHeldToTheWindow(): void
    {
        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $this->verifying->claims = $this->claimsAt($this->clock->now()->subDay());

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted(), (string) $completion->reason?->value);
        self::assertTrue($this->admit($completion, $start, Purpose::LINK, $this->person)->isRedeemed());
        self::assertSame(1, Link::query()->count());
    }

    /**
     * The OpenID Connect driver holds `auth_time` to the window: the reason it
     * refuses for, or the session renewed with exactly that time.
     *
     * @param  int  $seconds
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideAuthenticationTimes')]
    public function testOpenIdConnectHoldsAuthTimeToTheWindow(int $seconds, ?FailureReason $reason): void
    {
        $provider = $this->openIdProvider();

        $this->connection = $this->openIdConnection($provider);

        $this->hold(new LinkSubject($provider->issuer, FakeOpenIdProvider::SUBJECT));

        $started = $this->clock->now();
        $at      = $started->addSeconds($seconds);
        $start   = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        $this->clock->advance(self::ELAPSED);

        $grant = $provider->authorize((string) $start->navigation?->url(), static fn (FakeIdToken $token): FakeIdToken => $token->with('auth_time', $at->getTimestamp()));

        $this->assertEnds($this->answerCallback($grant->query()), $start, $reason, $at);
    }

    /**
     * An ID token with no `auth_time` is refused, whatever else it says.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testOpenIdConnectRefusesAnIdTokenWithNoAuthTime(): void
    {
        $provider = $this->openIdProvider();

        $this->connection = $this->openIdConnection($provider);

        $this->hold(new LinkSubject($provider->issuer, FakeOpenIdProvider::SUBJECT));

        $start = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
        $grant = $provider->authorize((string) $start->navigation?->url(), static fn (FakeIdToken $token): FakeIdToken => $token->without('auth_time'));

        $completion = $this->answerCallback($grant->query());

        self::assertSame([true, FailureReason::ID_TOKEN_INVALID, null], [$completion->isFailed(), $completion->reason, $completion->handoff]);
        self::assertSame(0, StoredCode::query()->count());
    }

    /**
     * Rows of the connection's settings, which a `reauthenticate` overrides.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideOpenIdSettings(): iterable
    {
        yield 'nothing configured' => [[]];
        yield 'its own maximum age' => [['max_age' => 3600]];
        yield 'its own prompt' => [['extra_parameters' => ['prompt' => 'none']]];
    }

    /**
     * The request sent forces fresh authentication: `prompt=login` with
     * `max_age=0`, whatever the connection configures, and each exactly once.
     *
     * @param  array<string, mixed>  $settings
     * @return void
     */
    #[DataProvider('provideOpenIdSettings')]
    public function testOpenIdConnectForcesFreshAuthentication(array $settings): void
    {
        $this->connection = $this->openIdConnection($this->openIdProvider(), $settings);

        $start = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
        $query = (string) parse_url((string) $start->navigation?->url(), PHP_URL_QUERY);

        self::assertSame(1, substr_count($query, 'prompt='));
        self::assertSame(1, substr_count($query, 'max_age='));
        self::assertStringContainsString('max_age=0&prompt=login', $query);
    }

    /**
     * A `sign_in` forces nothing of its own.
     *
     * @return void
     */
    public function testOpenIdConnectForcesNothingForASignIn(): void
    {
        $this->connection = $this->openIdConnection($this->openIdProvider());

        $query = (string) parse_url((string) $this->start()->navigation?->url(), PHP_URL_QUERY);

        self::assertStringNotContainsString('prompt=', $query);
        self::assertStringNotContainsString('max_age=', $query);
    }

    /**
     * The SAML driver holds the `AuthnInstant` to the window: the reason it
     * refuses for, or the session renewed with exactly that time.
     *
     * @param  int  $seconds
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideAuthenticationTimes')]
    public function testSamlHoldsTheAuthnInstantToTheWindow(int $seconds, ?FailureReason $reason): void
    {
        $this->connection = $this->samlConnection();

        $this->hold(self::samlSubject());

        $started = $this->clock->now();
        $at      = $started->addSeconds($seconds);
        $start   = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        $this->clock->advance(self::ELAPSED);

        $this->assertEnds($this->assertion($start, [$this->statement($at)]), $start, $reason, $at, Flow::ASSERTION);
    }

    /**
     * How many statements an assertion holds, other than one.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideStatementCounts(): iterable
    {
        yield 'none' => [0];
        yield 'two' => [2];
    }

    /**
     * An assertion without exactly one `AuthnStatement` states no single
     * authentication time, and is refused.
     *
     * @param  int  $statements
     * @return void
     */
    #[DataProvider('provideStatementCounts')]
    public function testSamlRefusesAnythingButOneStatement(int $statements): void
    {
        $this->connection = $this->samlConnection();

        $this->hold(self::samlSubject());

        $start      = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
        $completion = $this->assertion($start, array_fill(0, $statements, $this->statement($this->clock->now())));

        self::assertSame([true, FailureReason::RESPONSE_INVALID, null], [$completion->isFailed(), $completion->reason, $completion->handoff]);
        self::assertSame(0, StoredCode::query()->count());
    }

    /**
     * The request sent forces fresh authentication: `ForceAuthn="true"`, though
     * the connection does not; a `sign_in` through it does not.
     *
     * @return void
     */
    public function testSamlForcesFreshAuthentication(): void
    {
        $this->connection = $this->samlConnection();

        $reauthenticating = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
        $signingIn        = $this->start();

        self::assertSame('true', self::authnRequest($reauthenticating)->getAttribute('ForceAuthn'));
        self::assertFalse(self::authnRequest($signingIn)->hasAttribute('ForceAuthn'));
    }

    /**
     * Make a link of the subject for the person, through the store, on the
     * connection, and bind the session to it.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @return void
     */
    private function hold(LinkSubject $subject): void
    {
        $creation = app(LinkStore::class)->create($this->connection, $subject, $this->person, LinkOrigin::PROVISIONING, Clients::browser());

        self::assertTrue($creation->isCreated());

        $this->sessions->boundLink = Link::query()->whereKey($creation->link?->id)->sole()->id;
    }

    /**
     * The subject the fake identity provider's persistent `NameID` resolves to:
     * the driver stores the `NameID` with its qualifiers, length-prefixed.
     *
     * @return \SineMacula\Laravel\Sso\Links\LinkSubject
     */
    private static function samlSubject(): LinkSubject
    {
        $format = FakeSamlResponse::PERSISTENT;

        return new LinkSubject(FakeSamlIdentityProvider::ENTITY_ID, 'v1|7:name_id|52:' . $format . '|-|-|5:alice', $format);
    }

    /**
     * What the verifying driver verifies, authenticated at the instant.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @return \SineMacula\Laravel\Sso\Results\VerifiedClaims
     */
    private function claimsAt(CarbonImmutable $at): VerifiedClaims
    {
        return new VerifiedClaims(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT, null, ['mail' => self::EMAIL], new AuthenticationContext($at));
    }

    /**
     * Assert how the completion ended: refused for the reason, with no code and
     * nothing renewed; or completed, redeemed, and the session renewed with
     * exactly the provider's time.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $completion
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \Carbon\CarbonImmutable  $at
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @return void
     */
    private function assertEnds(CompletionResult $completion, StartResult $start, ?FailureReason $reason, CarbonImmutable $at, Flow $flow = Flow::CALLBACK): void
    {
        if ($reason !== null) {
            self::assertSame([true, $reason, null], [$completion->isFailed(), $completion->reason, $completion->handoff]);
            self::assertSame(0, StoredCode::query()->count());
            self::assertSame(0, $this->sessions->renewals());
            $this->assertExactlyOneFailure($flow, $reason);

            return;
        }

        self::assertSame([null, true], [$completion->reason, $completion->isCompleted()]);
        self::assertTrue($this->admit($completion, $start, Purpose::REAUTHENTICATE)->isAdmitted());
        self::assertSame(
            [[self::SESSION, $at->utc()->format(self::INSTANT), null]],
            array_map(static fn (array $renewal): array => [$renewal[0], $renewal[1]->utc()->format(self::INSTANT), $renewal[2]], $this->sessions->renewed),
        );
    }

    /**
     * The fake OpenID provider, on the fake fetcher, reading the clock.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider
     */
    private function openIdProvider(): FakeOpenIdProvider
    {
        $fetcher  = new FakeFetcher;
        $provider = (new FakeOpenIdProvider(FakeOpenIdProvider::ISSUER, self::key(), $this->clock))->serve($fetcher);

        $this->app?->instance(Fetcher::class, $fetcher);

        return $provider;
    }

    /**
     * An OpenID Connect connection trusting the provider's key.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function openIdConnection(FakeOpenIdProvider $provider, array $settings = []): Connection
    {
        $jwks = (string) json_encode(['keys' => [self::key()->jwk()]]);

        return $this->makeConnection([
            'enabled'  => true,
            'jwks'     => ProviderKeySet::read($jwks, AlgorithmAllowList::of(['RS256']), 65536, 50)?->toStored(),
            'secrets'  => app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret(FakeOpenIdProvider::CLIENT_SECRET)]),
            'settings' => [
                'issuer'                 => $provider->issuer,
                'authorization_endpoint' => $provider->endpoint('authorization'),
                'token_endpoint'         => $provider->endpoint('token'),
                'jwks_uri'               => $provider->endpoint('jwks'),
                'client_id'              => FakeOpenIdProvider::CLIENT_ID,
                ...$settings,
            ],
        ]);
    }

    /**
     * A SAML connection trusting the identity provider's certificate.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \LogicException
     */
    private function samlConnection(): Connection
    {
        $connection = $this->makeConnection([
            'protocol'          => 'saml2',
            'enabled'           => true,
            'settings'          => ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL],
            'attribute_mapping' => ['email' => 'email'],
        ]);

        $certificate = self::idp()->certificate();
        $details     = openssl_pkey_get_details(openssl_pkey_get_public($certificate) ?: throw new \LogicException('A certificate has a public key.'));

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'state'         => null,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $certificate,
            'public_key'    => is_array($details) ? $details['key'] : '',
            'private_key'   => null,
            'fingerprint'   => (string) openssl_x509_fingerprint($certificate, 'sha256'),
        ])->save();

        return $connection;
    }

    /**
     * Answer the OpenID Connect callback with the query.
     *
     * @param  string  $query
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function answerCallback(string $query): CompletionResult
    {
        return app(CompletionService::class)->complete(CompletionEndpoint::CALLBACK, $this->connection->id, new CompletionRequest('GET', $query, []), Clients::browser());
    }

    /**
     * Post the assertion consumer service the response to the flow's request,
     * from the identity provider, with the statements.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function assertion(StartResult $start, array $statements): CompletionResult
    {
        $endpoints = app(EndpointResolver::class)->endpoints($this->connection);
        $request   = AuthorizationRequest::query()->where('reference', $start->reference?->value)->sole();
        $response  = self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, $this->clock->now())
            ->with(['authn_statements' => $statements])
            ->inResponseTo($request->saml_request_id);

        parse_str((string) parse_url((string) $start->navigation?->url(), PHP_URL_QUERY), $query);

        /** @var array{RelayState?: string} $query */
        $posted = new CompletionRequest('POST', '', ['SAMLResponse' => $response->encoded(), 'RelayState' => $query['RelayState'] ?? '']);

        return app(CompletionService::class)->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $this->connection->id, $posted, Clients::browser());
    }

    /**
     * An authentication statement at the instant.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @return array<string, mixed>
     */
    private function statement(CarbonImmutable $at): array
    {
        return [
            'instant'                 => $at,
            'session_index'           => '_session-1',
            'session_not_on_or_after' => $this->clock->now()->addHours(8),
            'class'                   => FakeSamlResponse::PASSWORD_PROTECTED_TRANSPORT,
        ];
    }

    /**
     * The root element of the `AuthnRequest` the start's navigation carries.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return \DOMElement
     */
    private static function authnRequest(StartResult $start): \DOMElement
    {
        parse_str((string) parse_url((string) $start->navigation?->url(), PHP_URL_QUERY), $query);

        $encoded  = $query['SAMLRequest'] ?? null;
        $document = new \DOMDocument;

        self::assertIsString($encoded);
        self::assertTrue($document->loadXML((string) gzinflate((string) base64_decode($encoded, true)), LIBXML_NONET));
        self::assertNotNull($document->documentElement);

        return $document->documentElement;
    }

    /**
     * The OpenID provider's key.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(): FakeSigningKey
    {
        return self::$key ??= FakeSigningKey::rsa('rsa-1');
    }

    /**
     * The SAML identity provider.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }
}
