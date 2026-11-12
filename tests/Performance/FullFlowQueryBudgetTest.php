<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Discovery\DiscoveryService;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokenValidator;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Protocols\Oidc\TokenExchange;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesEnforcement;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;

/**
 * Query budgets for whole flows through the real drivers and stores, with
 * enforcement on and the counters apart, measured once the counters exist.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequestService::class)]
#[CoversClass(DiscoveryService::class)]
#[CoversClass(CompletionService::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(IdTokenValidator::class)]
#[CoversClass(TokenExchange::class)]
#[CoversClass(AssertionValidator::class)]
final class FullFlowQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections, UsesDomains, UsesEnforcement, UsesFlowTables;

    /** @var string The identity's type, as a link stores it. */
    private const string IDENTITY_TYPE = 'App\Models\User';

    /** @var string The identity's id, as a link stores it. */
    private const string IDENTITY_ID = '42';

    /** @var string The subject the fake identity provider's default `NameID` encodes to. */
    private const string SAML_SUBJECT = 'v1|7:name_id|52:' . FakeSamlResponse::PERSISTENT . '|-|-|5:alice';

    /** @var string An email of a domain that normalises, so its claim is read. */
    private const string EMAIL = 'person@example.com';

    /** @var string A callback's query the correlator refuses. */
    private const string REFUSED_QUERY = 'state=a&state=a';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The key the provider signs ID tokens with, made once. */
    private static ?FakeSigningKey $signingKey = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The connection's client assertion key, made once. */
    private static ?FakeSigningKey $clientKey = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var ?array{0: string, 1: string} The service provider's encryption key and certificate, made once. */
    private static ?array $spKeys = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The OpenID provider, its endpoints on the fake fetcher. */
    private FakeOpenIdProvider $provider;

    /**
     * Move the counters apart, bind the fake fetcher and the package's link
     * store, and configure the protocols, enforcement and discovery.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->useSeparateCounters();

        $fetcher        = new FakeFetcher;
        $this->provider = (new FakeOpenIdProvider(FakeOpenIdProvider::ISSUER, self::signingKey(), $this->clock))->serve($fetcher);

        $this->app?->instance(Fetcher::class, $fetcher);
        $this->app?->instance('request', Request::create('/auth/sso', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));
        $this->app?->instance(Linker::class, app(LinkStore::class));

        config()->set('sso.features.oidc', true);
        config()->set('sso.features.saml2', true);
        config()->set('sso.features.encrypted_assertions', true);
        config()->set('sso.features.enforcement', true);
        config()->set('sso.features.discovery', true);
        config()->set('sso.discovery.minimum_duration_milliseconds', 50);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', [
            'web'         => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
            'discovering' => [
                'redirect_uri'     => 'https://app.example.com/sso',
                'external_sign_in' => true,
                'discovery'        => ['enabled' => true, 'fallback_url' => 'https://app.example.com/sign-in'],
            ],
        ]);
    }

    /**
     * Start: the connection and its lock; the request and flows version.
     * Completion: the connection, two locks, JWKS, rule row, three locks, link;
     * use record, mark, rule upsert, link stamp, code, flows version, completed
     * mark. Redemption: code, tenant, rule row, two locks, link; rule upsert,
     * use record, mark, link stamp and the first sign-in's mark.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnOidcSignInFromStartToRedemption(): void
    {
        $connection = $this->openIdConnection();
        $version    = $this->enforcedThrough($connection);

        $this->createOpenIdCounters($connection);

        $first   = $this->assertQueryBudget(2, 2, fn (): StartResult => $this->startFlow($connection), 0, 1);
        $query   = $this->provider->authorize($this->urlOf($first))->query();
        $handoff = $this->assertQueryBudget(8, 7, fn (): CompletionResult => $this->completeAtCallback($connection, $query), 0, 2);
        $answer  = $this->assertQueryBudget(6, 5, fn (): RedemptionResult => $this->redeemCode($connection, $handoff, $first), 0, 1);

        self::assertTrue($answer->isRedeemed());
        self::assertSame(['type' => self::IDENTITY_TYPE, 'id' => self::IDENTITY_ID], $answer->linkedIdentity?->jsonSerialize());
        self::assertSame($version, $answer->enforcementVersion);
        self::assertSame(FakeOpenIdProvider::SUBJECT, $answer->result?->subject);
        self::assertTrue(Connection::query()->whereKey($connection->id)->sole()->has_completed_sign_in);

        $second = $this->assertQueryBudget(2, 2, fn (): StartResult => $this->startFlow($connection), 0, 1);
        $again  = $this->provider->authorize($this->urlOf($second))->query();
        $later  = $this->assertQueryBudget(8, 7, fn (): CompletionResult => $this->completeAtCallback($connection, $again), 0, 2);

        self::assertTrue($this->assertQueryBudget(6, 4, fn (): RedemptionResult => $this->redeemCode($connection, $later, $second), 0, 1)->isRedeemed());
    }

    /**
     * `private_key_jwt` adds the current key's read to the start and
     * redemption, and to the completion thrice plus its private half.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClientAssertionSignInFromStartToRedemption(): void
    {
        $this->provider->register(FakeOpenIdProvider::CLIENT_ID, 'private_key_jwt', null, self::clientKey()->publicKeyPem);

        $connection = $this->openIdConnection(['client_authentication' => 'private_key_jwt'], false);

        $this->storeClientKey($connection);
        $this->enforcedThrough($connection);
        $this->createOpenIdCounters($connection);

        $start   = $this->assertQueryBudget(3, 2, fn (): StartResult => $this->startFlow($connection), 0, 1);
        $query   = $this->provider->authorize($this->urlOf($start))->query();
        $handoff = $this->assertQueryBudget(12, 7, fn (): CompletionResult => $this->completeAtCallback($connection, $query), 0, 2);
        $answer  = $this->assertQueryBudget(7, 5, fn (): RedemptionResult => $this->redeemCode($connection, $handoff, $start), 0, 1);

        self::assertTrue($answer->isRedeemed());
        self::assertSame(self::IDENTITY_ID, $answer->linkedIdentity?->id);
    }

    /**
     * SAML reads its certificates at the start and redemption, and thrice in
     * the completion instead of the JWKS, plus the claim and replay record.
     *
     * @return void
     */
    public function testASamlSignInFromStartToRedemption(): void
    {
        $connection = $this->samlConnection();

        $this->enforcedThrough($connection);
        $this->createSamlCounters($connection);

        $start    = $this->assertQueryBudget(3, 2, fn (): StartResult => $this->startFlow($connection), 0, 1);
        $response = $this->samlRequest($start, $this->samlResponse($connection, $start));
        $handoff  = $this->assertQueryBudget(11, 8, fn (): CompletionResult => $this->completeAtAssertionConsumer($connection, $response), 0, 2);
        $answer   = $this->assertQueryBudget(7, 5, fn (): RedemptionResult => $this->redeemCode($connection, $handoff, $start), 0, 1);

        self::assertTrue($answer->isRedeemed());
        self::assertSame(self::SAML_SUBJECT, $answer->result?->subject);
        self::assertSame(self::IDENTITY_ID, $answer->linkedIdentity?->id);
    }

    /**
     * Encryption adds the current encryption key's read to each judgement, and
     * the decryption keys and private key to the completion.
     *
     * @return void
     */
    public function testAnEncryptedSamlSignInFromStartToRedemption(): void
    {
        $connection = $this->samlConnection(['require_encrypted_assertions' => true]);

        $this->storeSamlKey($connection, KeyUse::SP_ENCRYPTION, KeyState::CURRENT, self::spKeys()[1], self::spKeys()[0]);
        $this->enforcedThrough($connection);
        $this->createSamlCounters($connection);

        $start     = $this->assertQueryBudget(4, 2, fn (): StartResult => $this->startFlow($connection), 0, 1);
        $encrypted = $this->samlResponse($connection, $start)->encryptedFor(self::spKeys()[1]);
        $response  = $this->samlRequest($start, $encrypted);
        $handoff   = $this->assertQueryBudget(15, 8, fn (): CompletionResult => $this->completeAtAssertionConsumer($connection, $response), 0, 2);
        $answer    = $this->assertQueryBudget(8, 5, fn (): RedemptionResult => $this->redeemCode($connection, $handoff, $start), 0, 1);

        self::assertTrue($answer->isRedeemed());
        self::assertSame(self::SAML_SUBJECT, $answer->result?->subject);
    }

    /**
     * A discovery start adds the claim's read and the domain counter; its
     * completion the mapped email's claim.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testADiscoveryStartToCompletion(): void
    {
        $connection = $this->openIdConnection(mapping: ['email' => 'email']);

        $this->makeDomain($connection, 'example.com', ['state' => DomainState::VERIFIED]);
        $this->enforcedThrough($connection);

        $this->startByDiscovery();
        $this->completeAtCallback($connection, self::REFUSED_QUERY);

        $start  = $this->assertQueryBudget(3, 2, fn (): StartResult => $this->startByDiscovery(), 0, 2);
        $tailor = static fn (FakeIdToken $token): FakeIdToken => $token->with('email', self::EMAIL)->with('email_verified', true);
        $query  = $this->provider->authorize($this->urlOf($start), $tailor)->query();
        $result = $this->assertQueryBudget(9, 7, fn (): CompletionResult => $this->completeAtCallback($connection, $query), 0, 2);

        self::assertTrue($result->isCompleted());
        self::assertSame($connection->id, AuthorizationRequest::query()->where('reference', $start->reference?->value)->sole()->connection_id);
    }

    /**
     * Create the IP and connection counters with a start, a refused callback
     * and a value that is no code.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     */
    private function createOpenIdCounters(Connection $connection): void
    {
        $this->startFlow($connection);
        $this->completeAtCallback($connection, self::REFUSED_QUERY);
        $this->createRedemptionCounter($connection);
    }

    /**
     * Create the IP and connection counters with a start, an empty post and a
     * value that is no code.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     */
    private function createSamlCounters(Connection $connection): void
    {
        $this->startFlow($connection);
        $this->completeAtAssertionConsumer($connection, new CompletionRequest('POST', '', []));
        $this->createRedemptionCounter($connection);
    }

    /**
     * Create the redemption's counter, with a value that is no code.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     */
    private function createRedemptionCounter(Connection $connection): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $redemption = $app->make(HandoffRedemption::class);

        DB::connection(StorageConnection::name())->transaction(
            static fn (): RedemptionResult => $redemption->admit(Purpose::SIGN_IN, 'web', $connection->id, 'a-value-that-creates-the-counter', 'a-verifier', Clients::browser()),
        );
    }

    /**
     * Start a `sign_in` for `web` through the connection, the package
     * generating the verifier.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    private function startFlow(Connection $connection): StartResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(AuthorizationRequestService::class)->start('web', Purpose::SIGN_IN, $connection->id, Clients::browser());
    }

    /**
     * Start a `sign_in` for the discovering application by the email.
     *
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    private function startByDiscovery(): StartResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DiscoveryService::class)->start('discovering', Purpose::SIGN_IN, self::EMAIL, Clients::browser());
    }

    /**
     * Complete at the connection's callback with the query.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $query
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function completeAtCallback(Connection $connection, string $query): CompletionResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(CompletionService::class)->complete(CompletionEndpoint::CALLBACK, $connection->id, new CompletionRequest('GET', $query, []), Clients::browser());
    }

    /**
     * Complete at the connection's assertion consumer service.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function completeAtAssertionConsumer(Connection $connection, CompletionRequest $request): CompletionResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(CompletionService::class)->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $connection->id, $request, Clients::browser());
    }

    /**
     * Redeem the code as a `sign_in` for `web` in the caller's transaction,
     * with the start's verifier.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $completion
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function redeemCode(Connection $connection, CompletionResult $completion, StartResult $start): RedemptionResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $redemption = $app->make(HandoffRedemption::class);
        $code       = (string) $completion->handoff?->code->reveal();
        $verifier   = (string) $start->verifier?->reveal();

        return DB::connection(StorageConnection::name())->transaction(
            static fn (): RedemptionResult => $redemption->admit(Purpose::SIGN_IN, 'web', $connection->id, $code, $verifier, Clients::browser()),
        );
    }

    /**
     * Where the start sends the browser.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return string
     */
    private function urlOf(StartResult $start): string
    {
        return $start->navigation?->jsonSerialize()['url'] ?? '';
    }

    /**
     * A usable OIDC connection with its JWKS stored and its subject linked, by
     * client secret unless told otherwise.
     *
     * @param  array<string, mixed>  $settings
     * @param  bool  $secret
     * @param  array<string, string>  $mapping
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function openIdConnection(array $settings = [], bool $secret = true, array $mapping = []): Connection
    {
        $jwks = (string) json_encode($this->provider->jwks());

        $connection = $this->makeConnection([
            'enabled'           => true,
            'jwks'              => ProviderKeySet::read($jwks, AlgorithmAllowList::of(OidcSettings::ID_TOKEN_ALGORITHMS), 65536, 50)?->toStored(),
            'secrets'           => $secret ? app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret(FakeOpenIdProvider::CLIENT_SECRET)]) : null,
            'attribute_mapping' => $mapping,
            'settings'          => [
                'issuer'                 => $this->provider->issuer,
                'authorization_endpoint' => $this->provider->endpoint('authorization'),
                'token_endpoint'         => $this->provider->endpoint('token'),
                'jwks_uri'               => $this->provider->endpoint('jwks'),
                'client_id'              => FakeOpenIdProvider::CLIENT_ID,
                ...$settings,
            ],
        ]);

        $this->makeLink($connection, FakeOpenIdProvider::SUBJECT, [
            'issuer'        => $this->provider->issuer,
            'identity_type' => self::IDENTITY_TYPE,
            'identity_id'   => self::IDENTITY_ID,
        ]);

        return $connection;
    }

    /**
     * A usable SAML connection trusting the identity provider and mapping the
     * email, its subject linked.
     *
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function samlConnection(array $settings = []): Connection
    {
        $connection = $this->makeConnection([
            'protocol'          => 'saml2',
            'enabled'           => true,
            'attribute_mapping' => ['email' => 'email'],
            'settings'          => ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL, ...$settings],
        ]);

        $this->storeSamlKey($connection, KeyUse::IDP_SIGNING, null, self::idp()->certificate(), null);
        $this->makeLink($connection, self::SAML_SUBJECT, [
            'issuer'         => FakeSamlIdentityProvider::ENTITY_ID,
            'name_id_format' => FakeSamlResponse::PERSISTENT,
            'identity_type'  => self::IDENTITY_TYPE,
            'identity_id'    => self::IDENTITY_ID,
        ]);

        return $connection;
    }

    /**
     * Turn the tenant's enforcement on, satisfied by the connection, and answer
     * the rule's version.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return ?string
     */
    private function enforcedThrough(Connection $connection): ?string
    {
        return $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$connection->id]])->version;
    }

    /**
     * Store the connection's current client assertion key.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     */
    private function storeClientKey(Connection $connection): void
    {
        $key = self::clientKey();

        (new ConnectionKey)->forceFill([
            'connection_id'   => $connection->id,
            'use'             => KeyUse::CLIENT_ASSERTION,
            'state'           => KeyState::CURRENT,
            'key_type'        => KeyType::EC,
            'key_bits'        => 256,
            'public_key'      => $key->publicKeyPem,
            'private_key'     => app(SecretEncrypter::class)->encrypt($key->privateKeyPem),
            'fingerprint'     => hash('sha256', $key->publicKeyPem),
            'made_current_at' => $this->clock->now(),
        ])->save();
    }

    /**
     * Store a key or certificate of the use for the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  ?\SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @param  string  $certificate
     * @param  ?string  $privateKey
     * @return void
     *
     * @throws \LogicException
     */
    private function storeSamlKey(Connection $connection, KeyUse $use, ?KeyState $state, string $certificate, ?string $privateKey): void
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_public($certificate) ?: throw new \LogicException('A certificate has a public key.'));

        (new ConnectionKey)->forceFill([
            'connection_id'   => $connection->id,
            'use'             => $use,
            'state'           => $state,
            'key_type'        => KeyType::RSA,
            'key_bits'        => 2048,
            'certificate'     => $certificate,
            'public_key'      => is_array($details) ? $details['key'] : '',
            'private_key'     => $privateKey === null ? null : app(SecretEncrypter::class)->encrypt($privateKey),
            'fingerprint'     => (string) openssl_x509_fingerprint($certificate, 'sha256'),
            'made_current_at' => $state === null ? null : $this->clock->now(),
        ])->save();
    }

    /**
     * A valid response answering the start's request and asserting an email of
     * a real domain.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private function samlResponse(Connection $connection, StartResult $start): FakeSamlResponse
    {
        $endpoints = app(EndpointResolver::class)->endpoints($connection);
        $requestId = AuthorizationRequest::query()->where('reference', $start->reference?->value)->sole()->saml_request_id;

        return self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, $this->clock->now())
            ->inResponseTo($requestId)
            ->with(['attributes' => ['email' => [self::EMAIL]]]);
    }

    /**
     * The browser's post of the response to the assertion consumer service,
     * with the start's `RelayState`.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse  $response
     * @return \SineMacula\Laravel\Sso\Protocols\CompletionRequest
     */
    private function samlRequest(StartResult $start, FakeSamlResponse $response): CompletionRequest
    {
        parse_str((string) parse_url($this->urlOf($start), PHP_URL_QUERY), $query);

        return $response->completionRequest(is_string($query['RelayState'] ?? null) ? $query['RelayState'] : null);
    }

    /**
     * The key the provider signs ID tokens with, made once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function signingKey(): FakeSigningKey
    {
        return self::$signingKey ??= FakeSigningKey::rsa();
    }

    /**
     * The connection's client assertion key, made once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function clientKey(): FakeSigningKey
    {
        return self::$clientKey ??= FakeSigningKey::ec('client-assertion-key');
    }

    /**
     * The trusted identity provider, made once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }

    /**
     * The service provider's encryption key and certificate, made once for the
     * class.
     *
     * @return array{0: string, 1: string}
     */
    private static function spKeys(): array
    {
        return self::$spKeys ??= FakeSamlIdentityProvider::keyPair('sp.example.test');
    }
}
