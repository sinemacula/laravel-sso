<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Oidc;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchCredentials;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\CallbackCompletion;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokenValidator;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;
use SineMacula\Laravel\Sso\Protocols\Oidc\TokenExchange;
use SineMacula\Laravel\Sso\Protocols\Oidc\TokenResponseReader;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use SineMacula\Laravel\Sso\Testing\Oidc\JwsSigner;
use Tests\Concerns\DumpsValues;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Protocols\IdentifiedConnection;
use Tests\TestCase;

/**
 * Feature tests for the token request and reading its answer (SSO-5.4, SSO-7.2,
 * SSO-7.6): exactly one client authentication by the connection's method, with
 * no credential a `null`; the client assertion's claims and its `jti`, fresh on
 * each attempt; the exact form, timeout and cap; one attempt, never inside a
 * transaction; and every answer mapped to its exact reason, with the tokens the
 * only thing kept of a body.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TokenExchange::class)]
#[CoversClass(TokenResponseReader::class)]
final class TokenExchangeTest extends TestCase
{
    use DumpsValues, UsesConnections;

    /** @var string The token endpoint, as the connection holds it. */
    private const string TOKEN_ENDPOINT = 'https://op.example.test/oauth/token?tenant=a';

    /** @var string The client id. */
    private const string CLIENT_ID = 'client-1';

    /** @var string The client secret. */
    private const string SECRET = 'the-client-secret';

    /** @var string The PKCE verifier the request keeps. */
    private const string VERIFIER = 'the-pkce-verifier-of-the-exchanged-request-1';

    /** @var string The authorisation code. */
    private const string CODE = 'the-authorization-code';

    /** @var string The ID token an answer holds. */
    private const string ID_TOKEN = 'header.payload.signature';

    /** @var string The access token an answer holds. */
    private const string ACCESS_TOKEN = 'the-access-token';

    /** @var string The refresh token an answer holds, never kept. */
    private const string REFRESH_TOKEN = 'the-refresh-token-never-kept';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The connection's client assertion key, made once. */
    private static ?FakeSigningKey $clientKey = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the request is sent through. */
    private FakeFetcher $fetcher;

    /**
     * Bind a fixed clock and the fake fetcher, answering the token endpoint
     * with tokens, configure the endpoints, and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock   = new FixedClock('2026-11-01T09:30:00Z');
        $this->fetcher = new FakeFetcher;

        $this->fetcher->respond(self::TOKEN_ENDPOINT, self::answer());

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Fetcher::class, $this->fetcher);

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');

        $this->createConnectionTables();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * Rows of `[method, kind]`: a client secret method and what carries it.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind}>
     */
    public static function provideSecretMethods(): iterable
    {
        yield from [
            'basic' => ['client_secret_basic', CredentialKind::CLIENT_SECRET_BASIC],
            'post'  => ['client_secret_post', CredentialKind::CLIENT_SECRET_POST],
        ];
    }

    /**
     * A client secret method carries the client id and the stored secret, by
     * its own kind.
     *
     * @param  string  $method
     * @param  \SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind  $kind
     * @return void
     */
    #[DataProvider('provideSecretMethods')]
    public function testAClientSecretMethodCarriesTheSecret(string $method, CredentialKind $kind): void
    {
        $credentials = $this->credentialsOf($this->connection($method, self::SECRET));

        self::assertNotNull($credentials);
        self::assertSame([$kind, self::CLIENT_ID, self::SECRET], [$credentials->kind, $credentials->clientId, $credentials->secret()]);
    }

    /**
     * A client secret method with no secret set has no credential.
     *
     * @param  string  $method
     * @param  \SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind  $kind
     * @return void
     */
    #[DataProvider('provideSecretMethods')]
    public function testAClientSecretMethodWithNoSecretHasNoCredential(string $method, CredentialKind $kind): void
    {
        unset($kind);

        self::assertNull($this->credentialsOf($this->connection($method, null)));
    }

    /**
     * A connection given through its contract and gone has no secret, so no
     * credential.
     *
     * @return void
     */
    public function testAConnectionThatIsGoneHasNoCredential(): void
    {
        $connection = new IdentifiedConnection('01jbgoneconnection00000000', settings: self::settings('client_secret_basic'));

        self::assertNull(app(TokenExchange::class)->credentials($connection, OidcOptions::of($connection)));
    }

    /**
     * A method the package does not know has no credential, so the completion
     * fails closed.
     *
     * @return void
     */
    public function testAnUnknownMethodHasNoCredential(): void
    {
        $connection = new IdentifiedConnection('01jbunknownmethod000000000', settings: self::settings('tls_client_auth'));

        self::assertNull(app(TokenExchange::class)->credentials($connection, OidcOptions::of($connection)));
    }

    /**
     * `private_key_jwt` with no current key has no credential: a key waiting to
     * become current signs nothing.
     *
     * @return void
     */
    public function testPrivateKeyJwtWithNoCurrentKeyHasNoCredential(): void
    {
        $connection = $this->connection('private_key_jwt', null);

        self::assertNull($this->credentialsOf($connection));

        $this->clientKey($connection, KeyState::NEXT);

        self::assertNull($this->credentialsOf($connection));
    }

    /**
     * `private_key_jwt` carries the client id and an assertion of RFC 7523's
     * claims, verifying with the connection's current key: `iss` and `sub` the
     * client id, `aud` the token endpoint exactly, a fresh `jti`, `iat` now and
     * `exp` a minute later, under `typ` `JWT`, `ES256` and the key's `kid`.
     *
     * @return void
     */
    public function testPrivateKeyJwtCarriesAnAssertionOfTheCurrentKey(): void
    {
        $connection = $this->connection('private_key_jwt', null);

        $this->clientKey($connection, KeyState::CURRENT);

        $credentials = $this->credentialsOf($connection);

        self::assertNotNull($credentials);
        self::assertSame([CredentialKind::PRIVATE_KEY_JWT, self::CLIENT_ID], [$credentials->kind, $credentials->clientId]);

        $assertion = $credentials->secret();

        self::assertTrue(JwsSigner::verify($assertion, self::clientSigningKey()->publicKeyPem));

        [$header, $claims] = self::decoded($assertion);

        self::assertSame(['ES256', 'JWT'], [$header['alg'] ?? null, $header['typ'] ?? null]);
        self::assertIsString($header['kid'] ?? null);

        $now = $this->clock->now()->getTimestamp();

        self::assertIsString($claims['jti'] ?? null);
        self::assertSame(
            [self::CLIENT_ID, self::CLIENT_ID, self::TOKEN_ENDPOINT, $now, $now + 60],
            [$claims['iss'], $claims['sub'], $claims['aud'], $claims['iat'], $claims['exp']],
        );
    }

    /**
     * Each attempt signs a new assertion: its `jti` is new, under the same
     * stable `kid`.
     *
     * @return void
     */
    public function testEachAttemptSignsAFreshAssertion(): void
    {
        $connection = $this->connection('private_key_jwt', null);

        $this->clientKey($connection, KeyState::CURRENT);

        $first  = self::decoded((string) $this->credentialsOf($connection)?->secret());
        $second = self::decoded((string) $this->credentialsOf($connection)?->secret());

        self::assertNotSame($first[1]['jti'], $second[1]['jti']);
        self::assertSame($first[0]['kid'], $second[0]['kid']);
    }

    /**
     * The request is a token request to the token endpoint exactly, by `POST`,
     * with exactly the form RFC 6749 §4.1.3 and RFC 7636 §4.5 ask for, the
     * connection's callback as `redirect_uri`, one client authentication, and
     * the default timeout and cap.
     *
     * @return void
     */
    public function testSendsExactlyTheForm(): void
    {
        $connection = $this->connection('client_secret_basic', self::SECRET);
        $result     = $this->send($connection);
        $requests   = $this->fetcher->requests();

        self::assertTrue($result->isSuccessful());
        self::assertCount(1, $requests);

        $request = $requests[0];

        self::assertSame(
            [FetchPurpose::TOKEN, 'POST', self::TOKEN_ENDPOINT, CredentialKind::CLIENT_SECRET_BASIC, 10, 65536],
            [$request->purpose, $request->method(), $request->url, $request->credentials?->kind, $request->timeoutSeconds, $request->maxBytes],
        );
        self::assertSame([
            'grant_type'    => 'authorization_code',
            'code'          => self::CODE,
            'redirect_uri'  => 'https://sp.example.test/auth/sso/connections/' . $connection->id . '/callback',
            'code_verifier' => self::VERIFIER,
        ], $request->form());
    }

    /**
     * The timeout and the cap are read from the configuration, so a body over a
     * lowered cap fails.
     *
     * @return void
     */
    public function testHoldsTheRequestToTheConfiguredTimeoutAndCap(): void
    {
        config()->set('sso.oidc.token_timeout_seconds', 3);
        config()->set('sso.oidc.max_token_response_bytes', 4096);

        $this->fetcher->respond(self::TOKEN_ENDPOINT, FetchResult::fetched(200, [], str_repeat('x', 4097)));

        $result  = $this->send($this->connection('client_secret_basic', self::SECRET));
        $request = $this->fetcher->requests()[0];

        self::assertSame([3, 4096], [$request->timeoutSeconds, $request->maxBytes]);
        self::assertSame(FailureReason::FETCH_FAILED, (new TokenResponseReader)->refusal($result));
    }

    /**
     * A failed request is answered as it is, after one attempt: nothing retries
     * it.
     *
     * @return void
     */
    public function testMakesOneAttempt(): void
    {
        $failed = FetchResult::failed();

        $this->fetcher->respond(self::TOKEN_ENDPOINT, $failed);

        self::assertSame($failed, $this->send($this->connection('client_secret_basic', self::SECRET)));
        self::assertCount(1, $this->fetcher->requests());
    }

    /**
     * The request is never sent inside a transaction on the storage connection.
     *
     * @return void
     */
    public function testRefusesToSendInsideATransaction(): void
    {
        $connection = $this->connection('client_secret_basic', self::SECRET);
        $database   = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        try {
            $this->send($connection);
            self::fail('A token request inside a transaction must throw.');
        } catch (\LogicException $exception) {
            self::assertSame('A token request is sent outside any transaction on the package\'s storage connection: a provider call never holds a lock.', $exception->getMessage());
        } finally {
            $database->rollBack();
        }

        $this->fetcher->assertNothingFetched();
    }

    /**
     * A request that keeps no PKCE verifier is the caller's mistake, and
     * nothing is sent.
     *
     * @return void
     */
    public function testRefusesARequestWithNoVerifier(): void
    {
        try {
            $this->send($this->connection('client_secret_basic', self::SECRET), ['codeVerifier' => null]);
            self::fail('A request that keeps no verifier must throw.');
        } catch (\LogicException $exception) {
            self::assertSame('An OpenID Connect authorisation request keeps its PKCE verifier.', $exception->getMessage());
        }

        $this->fetcher->assertNothingFetched();
    }

    /**
     * A verifier no key decrypts propagates as a server error, and nothing is
     * sent.
     *
     * @return void
     */
    public function testAVerifierNoKeyDecryptsPropagates(): void
    {
        $connection = $this->connection('client_secret_basic', self::SECRET);

        $this->expectException(DecryptException::class);

        try {
            $this->send($connection, ['codeVerifier' => 'not-a-ciphertext']);
        } finally {
            $this->fetcher->assertNothingFetched();
        }
    }

    /**
     * Rows of `[answer, reason, provider error]`: what the endpoint answered,
     * why it is refused, and the provider's error read from it.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchResult, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason, 2: ?string}>
     */
    public static function provideAnswers(): iterable
    {
        $escaped = chr(92) . 'u0069d_token';
        $tokens  = ['id_token' => self::ID_TOKEN, 'access_token' => self::ACCESS_TOKEN, 'token_type' => 'Bearer'];
        $invalid = FailureReason::TOKEN_RESPONSE_INVALID;
        $number  = '123456789012345678901234567890';

        yield from [
            'tokens'                         => [FakeTokenEndpoint::json(200, $tokens), null, null],
            'tokens at the end of 2xx'       => [FakeTokenEndpoint::json(299, $tokens), null, null],
            'a lower-case token type'        => [FakeTokenEndpoint::json(200, [...$tokens, 'token_type' => 'bearer']), null, null],
            'an upper-case token type'       => [FakeTokenEndpoint::json(200, [...$tokens, 'token_type' => 'BEARER']), null, null],
            'unknown members'                => [FakeTokenEndpoint::json(200, [...$tokens, 'refresh_token' => self::REFRESH_TOKEN, 'scope' => ['a']]), null, null],
            'a refused request'              => [FetchResult::refused(), FailureReason::FETCH_REFUSED, null],
            'a failed request'               => [FetchResult::failed(), FailureReason::FETCH_FAILED, null],
            'a status before 2xx'            => [FakeTokenEndpoint::json(199, $tokens), FailureReason::FETCH_FAILED, null],
            'a status after 2xx'             => [FakeTokenEndpoint::json(300, $tokens), FailureReason::FETCH_FAILED, null],
            'a redirect'                     => [FetchResult::fetched(302, ['Location' => 'https://elsewhere.example.test'], ''), FailureReason::FETCH_FAILED, null],
            'invalid_grant'                  => [FakeTokenEndpoint::json(400, ['error' => 'invalid_grant', 'error_uri' => 'x']), FailureReason::PROVIDER_ERROR, 'invalid_grant'],
            'invalid_client'                 => [FakeTokenEndpoint::json(401, ['error' => 'invalid_client']), FailureReason::PROVIDER_ERROR, 'invalid_client'],
            'a 400 that is not JSON'         => [FetchResult::fetched(400, [], 'Bad Request'), FailureReason::FETCH_FAILED, null],
            'a 400 with no error'            => [FakeTokenEndpoint::json(400, ['message' => 'no']), FailureReason::FETCH_FAILED, null],
            'a 400 with an empty error'      => [FakeTokenEndpoint::json(400, ['error' => '']), FailureReason::FETCH_FAILED, null],
            'a 400 with a number error'      => [FakeTokenEndpoint::json(400, ['error' => 400]), FailureReason::FETCH_FAILED, null],
            'a 400 with a repeated error'    => [FetchResult::fetched(400, [], '{"error":"a","error":"b"}'), FailureReason::FETCH_FAILED, null],
            'a 402'                          => [FakeTokenEndpoint::json(402, ['error' => 'payment_required']), FailureReason::FETCH_FAILED, null],
            'a 403'                          => [FakeTokenEndpoint::json(403, ['error' => 'forbidden']), FailureReason::FETCH_FAILED, null],
            'a 500'                          => [FakeTokenEndpoint::json(500, ['error' => 'server_error']), FailureReason::FETCH_FAILED, null],
            'a 503'                          => [FetchResult::fetched(503, [], ''), FailureReason::FETCH_FAILED, null],
            'not JSON'                       => [FetchResult::fetched(200, [], 'id_token=a'), $invalid, null],
            'an empty body'                  => [FetchResult::fetched(200, [], ''), $invalid, null],
            'a JSON list'                    => [FetchResult::fetched(200, [], '["id_token"]'), $invalid, null],
            'a repeated member'              => [FetchResult::fetched(200, [], '{"id_token":"a","id_token":"b","access_token":"a","token_type":"Bearer"}'), $invalid, null],
            'a member repeated by an escape' => [FetchResult::fetched(200, [], '{"id_token":"a","' . $escaped . '":"b","access_token":"a","token_type":"Bearer"}'), $invalid, null],
            'no ID token'                    => [FakeTokenEndpoint::json(200, array_diff_key($tokens, ['id_token' => 1])), FailureReason::ID_TOKEN_INVALID, null],
            'an empty ID token'              => [FakeTokenEndpoint::json(200, [...$tokens, 'id_token' => '']), FailureReason::ID_TOKEN_INVALID, null],
            'a numeric ID token'             => [FakeTokenEndpoint::json(200, [...$tokens, 'id_token' => 42]), FailureReason::ID_TOKEN_INVALID, null],
            'a null ID token'                => [FakeTokenEndpoint::json(200, [...$tokens, 'id_token' => null]), FailureReason::ID_TOKEN_INVALID, null],
            'a list ID token'                => [FakeTokenEndpoint::json(200, [...$tokens, 'id_token' => ['a']]), FailureReason::ID_TOKEN_INVALID, null],
            'no access token'                => [FakeTokenEndpoint::json(200, array_diff_key($tokens, ['access_token' => 1])), $invalid, null],
            'an empty access token'          => [FakeTokenEndpoint::json(200, [...$tokens, 'access_token' => '']), $invalid, null],
            'a numeric access token'         => [FakeTokenEndpoint::json(200, [...$tokens, 'access_token' => 42]), $invalid, null],
            'an access token of many digits' => [FakeTokenEndpoint::json(200, [...$tokens, 'access_token' => $number]), null, null],
            'a large number access token'    => [FetchResult::fetched(200, [], '{"id_token":"a","access_token":' . $number . ',"token_type":"Bearer"}'), $invalid, null],
            'a large number ID token'        => [
                FetchResult::fetched(200, [], '{"id_token":' . $number . ',"access_token":"a","token_type":"Bearer"}'),
                FailureReason::ID_TOKEN_INVALID,
                null,
            ],
            'a 400 with a large number error' => [FetchResult::fetched(400, [], '{"error":' . $number . '}'), FailureReason::FETCH_FAILED, null],
            'an access token with a space'    => [FakeTokenEndpoint::json(200, [...$tokens, 'access_token' => 'a b']), $invalid, null],
            'an access token with a newline'  => [FakeTokenEndpoint::json(200, [...$tokens, 'access_token' => "a\n"]), $invalid, null],
            'no token type'                   => [FakeTokenEndpoint::json(200, array_diff_key($tokens, ['token_type' => 1])), $invalid, null],
            'the token type mac'              => [FakeTokenEndpoint::json(200, [...$tokens, 'token_type' => 'mac']), $invalid, null],
            'a numeric token type'            => [FakeTokenEndpoint::json(200, [...$tokens, 'token_type' => 1]), $invalid, null],
            'a token type with a space'       => [FakeTokenEndpoint::json(200, [...$tokens, 'token_type' => 'Bearer ']), $invalid, null],
        ];
    }

    /**
     * Each answer maps to its exact reason and provider's error.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $answer
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?string  $error
     * @return void
     */
    #[DataProvider('provideAnswers')]
    public function testMapsEachAnswerToItsReason(FetchResult $answer, ?FailureReason $reason, ?string $error): void
    {
        $reader = new TokenResponseReader;

        self::assertSame([$reason, $error], [$reader->refusal($answer), $reader->providerError($answer)]);
    }

    /**
     * An answer not refused gives the ID token, the access token and the token
     * type as the provider gave it, and nothing of the rest of the body, which
     * no dump of the tokens shows.
     *
     * @return void
     */
    public function testReadsTheTokensAndNothingElse(): void
    {
        $tokens = (new TokenResponseReader)->tokens(self::answer('bEaReR'));

        self::assertSame([self::ID_TOKEN, self::ACCESS_TOKEN, 'bEaReR'], [$tokens->idToken(), $tokens->accessToken(), $tokens->tokenType]);

        foreach (self::dumps($tokens) as $dump) {
            self::assertStringNotContainsString(self::REFRESH_TOKEN, $dump);
            self::assertStringNotContainsString(self::ACCESS_TOKEN, $dump);
            self::assertStringNotContainsString(self::ID_TOKEN, $dump);
        }
    }

    /**
     * Rows of `[answer]`: an answer holding no tokens.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchResult}>
     */
    public static function provideAnswersWithoutTokens(): iterable
    {
        yield from [
            'a failed request' => [FetchResult::failed()],
            'an error'         => [FakeTokenEndpoint::json(400, ['error' => 'invalid_grant'])],
            'no ID token'      => [FakeTokenEndpoint::json(200, ['access_token' => 'a', 'token_type' => 'Bearer'])],
        ];
    }

    /**
     * Asking for the tokens of a refused answer is the caller's mistake.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $answer
     * @return void
     */
    #[DataProvider('provideAnswersWithoutTokens')]
    public function testARefusedAnswerHoldsNoTokens(FetchResult $answer): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Only an answer that is not refused holds tokens.');

        (new TokenResponseReader)->tokens($answer);
    }

    /**
     * Through the completion, the tokens of the one attempt reach the ID
     * token's validation, whose double records them.
     *
     * @return void
     */
    public function testTheCompletionHandsOnTheTokensOfTheOneAttempt(): void
    {
        /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse> $seen */
        $seen = new \ArrayObject;

        $this->app?->instance(IdTokenValidator::class, new readonly class ($seen) extends IdTokenValidator {
            /**
             * Constructor.
             *
             * @param  \ArrayObject<int, \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse>  $seen
             *
             * @phpstan-ignore constructor.missingParentCall
             */
            public function __construct(

                /** What it was given. */
                private \ArrayObject $seen,
            ) {}

            /**
             * Record the tokens and refuse them.
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
                unset($connection, $options, $consumed);

                $this->seen->append($tokens);

                return IdTokenValidation::refused(FailureReason::SIGNATURE_INVALID);
            }
        });

        $connection = $this->connection('client_secret_post', self::SECRET);
        $arrival    = new CompletionRequest('GET', 'code=' . self::CODE, []);
        $completion = app(CallbackCompletion::class)->complete($connection, OidcOptions::of($connection), $arrival, $this->consumed());

        self::assertSame(FailureReason::SIGNATURE_INVALID, $completion->reason);
        self::assertCount(1, $this->fetcher->requests());
        self::assertCount(1, $seen);
        self::assertSame(self::ACCESS_TOKEN, ($seen[0] ?? self::fail('Nothing was validated.'))->accessToken());
    }

    /**
     * Send the token request through the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  array<string, mixed>  $consumed
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     *
     * @throws \LogicException
     */
    private function send(Connection $connection, array $consumed = []): FetchResult
    {
        $exchange    = app(TokenExchange::class);
        $options     = OidcOptions::of($connection);
        $credentials = FetchCredentials::clientSecretBasic(self::CLIENT_ID, self::SECRET);

        return $exchange->send($connection, $options, self::CODE, $this->consumed($consumed), $credentials);
    }

    /**
     * The credential the connection's settings name.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return ?\SineMacula\Laravel\Sso\Fetching\FetchCredentials
     */
    private function credentialsOf(Connection $connection): ?FetchCredentials
    {
        return app(TokenExchange::class)->credentials($connection, OidcOptions::of($connection));
    }

    /**
     * The request the code answers, with the changes given.
     *
     * @param  array<string, mixed>  $changes
     * @return \SineMacula\Laravel\Sso\Protocols\ConsumedRequest
     */
    private function consumed(array $changes = []): ConsumedRequest
    {
        $encrypter = app(SecretEncrypter::class);

        return new ConsumedRequest(...[
            'purpose'      => Purpose::SIGN_IN,
            'application'  => 'web',
            'reference'    => RequestReference::fromString('Sq8tVv3w0kLmNoPqRsTuVwXyZ0123456'),
            'startedAt'    => $this->clock->now(),
            'codeVerifier' => $encrypter->encrypt(self::VERIFIER),
            'encrypter'    => $encrypter,
            ...$changes,
        ]);
    }

    /**
     * An enabled connection authenticating by the method, with the client
     * secret given, if any.
     *
     * @param  string  $method
     * @param  ?string  $secret
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connection(string $method, ?string $secret): Connection
    {
        return $this->makeConnection([
            'enabled'  => true,
            'settings' => self::settings($method),
            'secrets'  => $secret === null ? null : app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret($secret)]),
        ]);
    }

    /**
     * Store the connection's client assertion key in the state.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @return void
     */
    private function clientKey(Connection $connection, KeyState $state): void
    {
        $key = self::clientSigningKey();

        (new ConnectionKey)->forceFill([
            'connection_id'   => $connection->id,
            'use'             => KeyUse::CLIENT_ASSERTION,
            'state'           => $state,
            'key_type'        => KeyType::EC,
            'key_bits'        => 256,
            'public_key'      => $key->publicKeyPem,
            'private_key'     => app(SecretEncrypter::class)->encrypt($key->privateKeyPem),
            'fingerprint'     => hash('sha256', $key->publicKeyPem),
            'made_current_at' => $state === KeyState::CURRENT ? $this->clock->now() : null,
        ])->save();
    }

    /**
     * The settings of a connection authenticating by the method.
     *
     * @param  string  $method
     * @return array<string, string>
     */
    private static function settings(string $method): array
    {
        return [
            'issuer'                 => 'https://op.example.test',
            'authorization_endpoint' => 'https://op.example.test/authorize',
            'token_endpoint'         => self::TOKEN_ENDPOINT,
            'jwks_uri'               => 'https://op.example.test/jwks',
            'client_id'              => self::CLIENT_ID,
            'client_authentication'  => $method,
        ];
    }

    /**
     * What the token endpoint answers with tokens, a refresh token among them.
     *
     * @param  string  $tokenType
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     */
    private static function answer(string $tokenType = 'Bearer'): FetchResult
    {
        return FakeTokenEndpoint::json(200, [
            'id_token'      => self::ID_TOKEN,
            'access_token'  => self::ACCESS_TOKEN,
            'token_type'    => $tokenType,
            'refresh_token' => self::REFRESH_TOKEN,
        ]);
    }

    /**
     * A compact token's header and claims.
     *
     * @param  string  $token
     * @return array{0: array<string, mixed>, 1: array<string, mixed>}
     */
    private static function decoded(string $token): array
    {
        $parts = explode('.', $token);

        /** @var array{0: array<string, mixed>, 1: array<string, mixed>} */
        return [json_decode(JwsSigner::decode($parts[0]), true), json_decode(JwsSigner::decode($parts[1] ?? ''), true)];
    }

    /**
     * The connection's client assertion key, made once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function clientSigningKey(): FakeSigningKey
    {
        return self::$clientKey ??= FakeSigningKey::ec('client-assertion-key');
    }
}
