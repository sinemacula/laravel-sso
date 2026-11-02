<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\CallbackCompletion;
use SineMacula\Laravel\Sso\Protocols\Oidc\CallbackCorrelator;
use SineMacula\Laravel\Sso\Protocols\Oidc\ClaimsAssembler;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokenValidator;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;
use SineMacula\Laravel\Sso\Protocols\Oidc\TokenExchange;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;

/**
 * Query budgets for the OpenID Connect callback (SSO-5.4, SSO-7.1, SSO-7.2,
 * SSO-11.3, SSO-11.5), with doubles of the ID token's validation and the
 * claims' assembly and no mapped email, so no domain is read, each measured
 * once the IP address's and the connection's counters exist, so every callback
 * first costs their two updates:
 *
 * - a query the correlator refuses is the connection's read alone;
 * - a client secret is held on the row already read, so a verified callback is
 *   the connection's read and the two pairs of locking reads, and a callback
 *   refused once its request is consumed the same, with or without a token
 *   request: five reads, with the request's consumption, its single-use record
 *   and its completion the three writes beside the counters';
 * - `private_key_jwt` reads the current key to judge the connection complete,
 *   before it validates and again under the lock, and to sign, with its private
 *   half: four more reads for a verified callback, one for a callback refused
 *   before the token request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(CallbackCorrelator::class)]
#[CoversClass(CallbackCompletion::class)]
#[CoversClass(TokenExchange::class)]
final class OidcCallbackQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var string The state of a callback the correlator refuses, repeated. */
    private const string REFUSED_QUERY = 'state=a&state=a';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The connection's client assertion key, made once. */
    private static ?FakeSigningKey $clientKey = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider, whose token endpoint answers with tokens. */
    private FakeOpenIdProvider $provider;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection, authenticating by `client_secret_basic`. */
    private Connection $connection;

    /**
     * Bind the recording issuer, a linker, the fake fetcher, the doubles and a
     * request from an IP address, configure the endpoints and the application,
     * make a usable connection, and create the counters.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $fetcher        = new FakeFetcher;
        $this->provider = (new FakeOpenIdProvider(clock: $this->clock))->serve($fetcher);

        $this->provider->respond('token', FakeTokenEndpoint::json(200, ['id_token' => 'header.payload.signature', 'access_token' => 'the-access-token', 'token_type' => 'Bearer']));

        $this->app?->instance(Fetcher::class, $fetcher);
        $this->app?->instance(HandoffIssuer::class, new RecordingHandoffIssuer);
        $this->app?->instance(Linker::class, new readonly class implements Linker {
            /**
             * One identity for every result.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
             */
            #[\Override]
            public function resolve(VerifiedResult $result): IdentityReference
            {
                unset($result);

                return new IdentityReference('App\Models\User', '42');
            }
        });
        $this->app?->instance('request', Request::create('/auth/sso/connections/x/callback', 'GET', server: ['REMOTE_ADDR' => '203.0.113.7']));

        $this->bindDoubles();

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $this->connection = $this->connectionWith('client_secret_basic', true);

        $this->complete($this->connection, self::REFUSED_QUERY);
    }

    /**
     * A query the correlator refuses reads the connection alone and writes only
     * the counters.
     *
     * @return void
     */
    public function testARefusedQueryIsTheConnectionsReadAlone(): void
    {
        $result = $this->assertQueryBudget(1, 2, fn (): CompletionResult => $this->complete($this->connection, self::REFUSED_QUERY));

        self::assertSame(FailureReason::REQUEST_UNKNOWN, $result->reason);
    }

    /**
     * A callback refused for its `iss`, before the token request, is five reads
     * and five writes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACallbackRefusedForItsIssuerIsFiveReadsAndFiveWrites(): void
    {
        $query  = $this->started($this->connection, 'iss=https%3A%2F%2Fother.example.test');
        $result = $this->assertQueryBudget(5, 5, fn (): CompletionResult => $this->complete($this->connection, $query));

        self::assertSame(FailureReason::ISSUER_MISMATCH, $result->reason);
    }

    /**
     * A callback refused at the token endpoint costs nothing more than one
     * refused before it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACallbackRefusedAtTheTokenEndpointIsFiveReadsAndFiveWrites(): void
    {
        $this->provider->respond('token', FetchResult::failed());

        $query  = $this->started($this->connection);
        $result = $this->assertQueryBudget(5, 5, fn (): CompletionResult => $this->complete($this->connection, $query));

        self::assertSame(FailureReason::FETCH_FAILED, $result->reason);
    }

    /**
     * A verified callback by a client secret is five reads and five writes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAVerifiedCallbackIsFiveReadsAndFiveWrites(): void
    {
        $query  = $this->started($this->connection);
        $result = $this->assertQueryBudget(5, 5, fn (): CompletionResult => $this->complete($this->connection, $query));

        self::assertTrue($result->isCompleted());
    }

    /**
     * `private_key_jwt` adds one read of the current key to a callback refused
     * before the token request.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClientAssertionConnectionRefusedFirstAddsOneRead(): void
    {
        $connection = $this->clientAssertionConnection();
        $query      = $this->started($connection, 'iss=https%3A%2F%2Fother.example.test');
        $result     = $this->assertQueryBudget(6, 5, fn (): CompletionResult => $this->complete($connection, $query));

        self::assertSame(FailureReason::ISSUER_MISMATCH, $result->reason);
    }

    /**
     * `private_key_jwt` adds four reads to a verified callback: the current key
     * before it validates, to sign, and under the lock, and its private half.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAVerifiedClientAssertionCallbackIsNineReadsAndFiveWrites(): void
    {
        $connection = $this->clientAssertionConnection();
        $query      = $this->started($connection);
        $result     = $this->assertQueryBudget(9, 5, fn (): CompletionResult => $this->complete($connection, $query));

        self::assertTrue($result->isCompleted());
    }

    /**
     * Complete at the callback of the connection with the query.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $query
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(Connection $connection, string $query): CompletionResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(CompletionService::class)->callback($connection->id, new CompletionRequest('GET', $query, []));
    }

    /**
     * Store a request through the connection, and answer the query of the
     * callback that answers it, with the extra parameter given.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?string  $extra
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function started(Connection $connection, ?string $extra = null): string
    {
        $state = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');

        $this->makeAuthorizationRequest($connection, [
            'state_digest'    => hash('sha256', $state),
            'nonce_digest'    => hash('sha256', 'the-nonce'),
            'code_verifier'   => app(SecretEncrypter::class)->encrypt('the-pkce-verifier-of-the-budgeted-request-01'),
            'expected_issuer' => $this->provider->issuer,
        ]);

        return 'code=the-code&state=' . $state . ($extra === null ? '' : '&' . $extra);
    }

    /**
     * An enabled connection of the provider authenticating by the method, with
     * no attribute mapping, and its client secret when asked.
     *
     * @param  string  $method
     * @param  bool  $secret
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connectionWith(string $method, bool $secret): Connection
    {
        return $this->makeConnection([
            'enabled'  => true,
            'secrets'  => $secret ? app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret(FakeOpenIdProvider::CLIENT_SECRET)]) : null,
            'settings' => [
                'issuer'                 => $this->provider->issuer,
                'authorization_endpoint' => $this->provider->endpoint('authorization'),
                'token_endpoint'         => $this->provider->endpoint('token'),
                'jwks_uri'               => $this->provider->endpoint('jwks'),
                'client_id'              => FakeOpenIdProvider::CLIENT_ID,
                'client_authentication'  => $method,
            ],
        ]);
    }

    /**
     * A usable connection authenticating by `private_key_jwt`, whose counter
     * exists.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function clientAssertionConnection(): Connection
    {
        $connection = $this->connectionWith('private_key_jwt', false);

        $this->clientKey($connection);
        $this->complete($connection, self::REFUSED_QUERY);

        return $connection;
    }

    /**
     * Store the connection's current client assertion key.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     */
    private function clientKey(Connection $connection): void
    {
        $key = self::$clientKey ??= FakeSigningKey::ec('client-assertion-key');

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
     * Bind doubles of the ID token's validation and the claims' assembly, which
     * validate and verify every token and read nothing.
     *
     * @return void
     */
    private function bindDoubles(): void
    {
        $this->app?->instance(IdTokenValidator::class, new readonly class extends IdTokenValidator {
            /**
             * Constructor: it needs none of what the real validation needs.
             *
             * @phpstan-ignore constructor.missingParentCall
             */
            public function __construct() {}

            /**
             * Validate the token.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
             * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse  $tokens
             * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
             * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation
             */
            #[\Override]
            public function validate(SsoConnection $connection, OidcOptions $options, TokenResponse $tokens, ConsumedRequest $consumed): IdTokenValidation
            {
                unset($connection, $tokens, $consumed);

                return IdTokenValidation::validated(new ValidatedIdToken($options->issuer(), 'the-subject', ['iss' => $options->issuer(), 'sub' => 'the-subject']));
            }
        });

        $this->app?->instance(ClaimsAssembler::class, new readonly class extends ClaimsAssembler {
            /**
             * Constructor: it needs none of what the real assembly needs.
             *
             * @phpstan-ignore constructor.missingParentCall
             */
            public function __construct() {}

            /**
             * Verify the token's issuer and a fixed subject.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
             * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken  $idToken
             * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse  $tokens
             * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
             * @return \SineMacula\Laravel\Sso\Protocols\Completion
             */
            #[\Override]
            public function assemble(SsoConnection $connection, OidcOptions $options, ValidatedIdToken $idToken, TokenResponse $tokens, ConsumedRequest $consumed): Completion
            {
                unset($connection, $options, $tokens, $consumed);

                return Completion::verified(new VerifiedClaims($idToken->issuer, 'the-subject', null, [], new AuthenticationContext));
            }
        });
    }
}
