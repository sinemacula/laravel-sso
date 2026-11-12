<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Oidc;

use Illuminate\Contracts\Encryption\DecryptException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\CallbackCompletion;
use SineMacula\Laravel\Sso\Protocols\Oidc\ClaimsAssembler;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokenValidator;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for judging an OpenID Connect callback against its consumed
 * request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CallbackCompletion::class)]
final class CallbackCompletionTest extends TestCase
{
    use CapturesLogs, UsesConnections;

    /** @var string The request's public reference. */
    private const string REFERENCE = 'Sq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /** @var string The PKCE verifier the request keeps. */
    private const string VERIFIER = 'the-pkce-verifier-of-the-consumed-request-1';

    /** @var string The ID token the token endpoint answers. */
    private const string ID_TOKEN = 'header.payload.signature';

    /** @var string The access token the token endpoint answers. */
    private const string ACCESS_TOKEN = 'the-access-token';

    /** @var string The subject the validated token names. */
    private const string SUBJECT = 'the-subject';

    /** @var string What an `error_description` holds, never logged. */
    private const string DESCRIPTION = 'description-never-logged';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's key, made once. */
    private static ?FakeSigningKey $key = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the token request is sent through. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider. */
    private FakeOpenIdProvider $provider;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection, with a client secret. */
    private Connection $connection;

    /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse> What the validation double was given. */
    private \ArrayObject $validated;

    /** @var \ArrayObject<int, array{0: \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken, 1: \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse}> What the assembly double was given. */
    private \ArrayObject $assembled;

    /** @var \ArrayObject<string, mixed> What the doubles answer, by `validation` and `completion`. */
    private \ArrayObject $answers;

    /**
     * Bind a fixed clock, the fake fetcher and the doubles, serve the provider,
     * make the connection, and capture logs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock     = new FixedClock('2026-11-01T09:30:00Z');
        $this->fetcher   = new FakeFetcher;
        $this->validated = new \ArrayObject;
        $this->assembled = new \ArrayObject;
        $this->provider  = new FakeOpenIdProvider(signingKey: self::key(), clock: $this->clock);

        $token = new ValidatedIdToken($this->provider->issuer, self::SUBJECT, ['iss' => $this->provider->issuer, 'sub' => self::SUBJECT]);

        /** @var \ArrayObject<string, mixed> $answers */
        $answers = new \ArrayObject([
            'validation' => IdTokenValidation::validated($token),
            'completion' => Completion::verified(new VerifiedClaims($this->provider->issuer, self::SUBJECT, null, [], new AuthenticationContext)),
        ]);

        $this->answers = $answers;

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Fetcher::class, $this->fetcher);
        $this->bindDoubles();

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');

        $this->usePackageTables();

        $this->provider->serve($this->fetcher);
        $this->provider->respond('token', FakeTokenEndpoint::json(200, [
            'id_token'      => self::ID_TOKEN,
            'access_token'  => self::ACCESS_TOKEN,
            'token_type'    => 'Bearer',
            'refresh_token' => 'never-kept',
        ]));

        $this->connection = $this->oidc(['client_authentication' => 'client_secret_basic']);

        $this->captureLogs();
    }

    /**
     * A query the correlator would have refused, read again here, is
     * `response_invalid`, with no provider called and nothing logged.
     *
     * @return void
     */
    public function testAQueryRefusedOnTheSecondReadIsAnInvalidResponse(): void
    {
        $completion = $this->complete('code=a&state=b&state=c');

        self::assertSame(FailureReason::RESPONSE_INVALID, $completion->reason);
        $this->fetcher->assertNothingFetched();
        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * Rows of `[iss, expected issuer, required, accepted]`.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: bool, 3: bool}>
     */
    public static function provideIssuers(): iterable
    {
        $issuer = FakeOpenIdProvider::ISSUER;

        yield from [
            'absent and not required'          => [null, $issuer, false, true],
            'absent and required'              => [null, $issuer, true, false],
            'absent, with no issuer recorded'  => [null, null, false, true],
            'equal and not required'           => [$issuer, $issuer, false, true],
            'equal and required'               => [$issuer, $issuer, true, true],
            'another provider'                 => ['https://other.example.test', $issuer, false, false],
            'another provider and required'    => ['https://other.example.test', $issuer, true, false],
            'a trailing slash'                 => [$issuer . '/', $issuer, false, false],
            'another case'                     => [strtoupper($issuer), $issuer, false, false],
            'empty'                            => ['', $issuer, false, false],
            'present, with no issuer recorded' => [$issuer, null, false, false],
        ];
    }

    /**
     * A present `iss` must equal the request's issuer byte for byte, and an
     * absent one is refused when required.
     *
     * @param  ?string  $iss
     * @param  ?string  $expected
     * @param  bool  $required
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideIssuers')]
    public function testHoldsTheIssuerToTheRequest(?string $iss, ?string $expected, bool $required, bool $accepted): void
    {
        $query      = 'code=the-code' . ($iss === null ? '' : '&iss=' . rawurlencode($iss));
        $completion = $this->complete($query, ['expectedIssuer' => $expected, 'issuerRequired' => $required]);

        self::assertSame($accepted ? null : FailureReason::ISSUER_MISMATCH, $completion->reason);
        self::assertCount($accepted ? 1 : 0, $this->fetcher->requests());
    }

    /**
     * `iss` is checked before the response is handled as an error: a wrong one
     * on an error response is `issuer_mismatch`, and the error is not logged.
     *
     * @return void
     */
    public function testChecksTheIssuerBeforeTheError(): void
    {
        $completion = $this->complete('error=access_denied&iss=https%3A%2F%2Fother.example.test');

        self::assertSame(FailureReason::ISSUER_MISMATCH, $completion->reason);
        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * Rows of `[query, reason]`: a response whose `error` and `code` refuse it.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideResponses(): iterable
    {
        yield from [
            'an error and a code'        => ['error=access_denied&code=the-code', FailureReason::RESPONSE_INVALID],
            'an error and an empty code' => ['error=access_denied&code=', FailureReason::RESPONSE_INVALID],
            'an empty error and a code'  => ['error=&code=the-code', FailureReason::RESPONSE_INVALID],
            'neither'                    => ['state=the-state', FailureReason::RESPONSE_INVALID],
            'an empty code'              => ['code=', FailureReason::RESPONSE_INVALID],
            'an error alone'             => ['error=access_denied', FailureReason::PROVIDER_ERROR],
            'an empty error alone'       => ['error=', FailureReason::PROVIDER_ERROR],
        ];
    }

    /**
     * Each is refused for its reason, with no provider called.
     *
     * @param  string  $query
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideResponses')]
    public function testHoldsTheResponseToExactlyACodeOrAnError(string $query, FailureReason $reason): void
    {
        self::assertSame($reason, $this->complete($query)->reason);
        $this->fetcher->assertNothingFetched();
        self::assertCount($reason === FailureReason::PROVIDER_ERROR ? 1 : 0, $this->capturedLogRecords());
    }

    /**
     * An error alone logs its code, the connection and the request's reference,
     * and nothing of `error_description` or `error_uri`.
     *
     * @return void
     */
    public function testAnErrorIsLoggedByItsCodeAlone(): void
    {
        $this->complete('error=access_denied&error_description=' . self::DESCRIPTION . '&error_uri=https%3A%2F%2Fop.example.test%2F' . self::DESCRIPTION);

        self::assertSame([[
            'channel' => 'sso_capture',
            'level'   => 'notice',
            'message' => 'sso.oidc.callback_error',
            'context' => ['connection_id' => $this->connection->id, 'request_reference' => self::REFERENCE, 'error' => 'access_denied'],
        ]], $this->capturedLogRecords());
    }

    /**
     * Rows of `[error, logged]`: what is logged of an `error`, by its shape.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideErrorCodes(): iterable
    {
        $long = str_repeat('abcdefgh.', 7) . 'a';

        yield from [
            'a registered code'  => ['temporarily_unavailable', 'temporarily_unavailable'],
            'an extension code'  => ['urn:vendor.error-1', 'urn:vendor.error-1'],
            'one byte'           => ['x', 'x'],
            'at the cap'         => [$long, $long],
            'over the cap'       => [$long . 'a', '[unrecognized]'],
            'prose'              => ['user jane is blocked', '[unrecognized]'],
            'a quote'            => ['a"b', '[unrecognized]'],
            'an accented letter' => ['café', '[unrecognized]'],
            'an equals sign'     => ['a=b', '[unrecognized]'],
            'empty'              => ['', '[unrecognized]'],
        ];
    }

    /**
     * Only what has the shape of a code is logged, so prose a provider puts in
     * `error` reaches no log.
     *
     * @param  string  $error
     * @param  string  $logged
     * @return void
     */
    #[DataProvider('provideErrorCodes')]
    public function testLogsOnlyWhatHasTheShapeOfACode(string $error, string $logged): void
    {
        self::assertSame(FailureReason::PROVIDER_ERROR, $this->complete('error=' . rawurlencode($error))->reason);
        self::assertSame($logged, $this->capturedLogRecords()[0]['context']['error']);
    }

    /**
     * An error the token endpoint answers is logged by its code alone, under
     * its own message.
     *
     * @return void
     */
    public function testATokenEndpointErrorIsLoggedByItsCodeAlone(): void
    {
        $this->provider->respond('token', FakeTokenEndpoint::json(400, ['error' => 'invalid_grant', 'error_description' => self::DESCRIPTION, 'error_uri' => self::DESCRIPTION]));

        self::assertSame(FailureReason::PROVIDER_ERROR, $this->complete('code=the-code')->reason);
        self::assertSame([[
            'channel' => 'sso_capture',
            'level'   => 'notice',
            'message' => 'sso.oidc.token_error',
            'context' => ['connection_id' => $this->connection->id, 'request_reference' => self::REFERENCE, 'error' => 'invalid_grant'],
        ]], $this->capturedLogRecords());
    }

    /**
     * An answer refused for anything but a provider's error logs nothing here:
     * the fetcher has logged what it knows.
     *
     * @return void
     */
    public function testARefusedAnswerThatIsNoProviderErrorLogsNothing(): void
    {
        $this->provider->respond('token', FetchResult::failed());

        self::assertSame(FailureReason::FETCH_FAILED, $this->complete('code=the-code')->reason);
        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * Rows of `[status, body, reason]`: an answer read for its reason.
     *
     * @return iterable<string, array{0: int, 1: string, 2: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideAnswers(): iterable
    {
        yield from [
            'a server error'  => [500, '{"error":"server_error"}', FailureReason::FETCH_FAILED],
            'a client error'  => [403, '{"error":"forbidden"}', FailureReason::FETCH_FAILED],
            'a redirect'      => [302, '', FailureReason::FETCH_FAILED],
            'not JSON'        => [200, '<html></html>', FailureReason::TOKEN_RESPONSE_INVALID],
            'no ID token'     => [200, '{"access_token":"a","token_type":"Bearer"}', FailureReason::ID_TOKEN_INVALID],
            'no access token' => [200, '{"id_token":"a","token_type":"Bearer"}', FailureReason::TOKEN_RESPONSE_INVALID],
            'no token type'   => [200, '{"id_token":"a","access_token":"a"}', FailureReason::TOKEN_RESPONSE_INVALID],
        ];
    }

    /**
     * The token endpoint's answer refuses the completion for the reason the
     * reader gives, with the doubles never asked.
     *
     * @param  int  $status
     * @param  string  $body
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideAnswers')]
    public function testARefusedAnswerGoesNoFurther(int $status, string $body, FailureReason $reason): void
    {
        $this->provider->respond('token', FetchResult::fetched($status, [], $body));

        self::assertSame($reason, $this->complete('code=the-code')->reason);
        self::assertCount(0, $this->validated);
        self::assertCount(0, $this->assembled);
    }

    /**
     * A connection whose client secret is not set is `connection_unavailable`,
     * with no provider called.
     *
     * @return void
     */
    public function testNoClientSecretIsConnectionUnavailable(): void
    {
        $connection = $this->makeConnection(['enabled' => true, 'settings' => self::settings()]);

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->complete('code=the-code', [], $connection)->reason);
        $this->fetcher->assertNothingFetched();
    }

    /**
     * A `private_key_jwt` connection with no current key is
     * `connection_unavailable`, with no provider called.
     *
     * @return void
     */
    public function testNoClientAssertionKeyIsConnectionUnavailable(): void
    {
        $connection = $this->oidc(['client_authentication' => 'private_key_jwt']);

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->complete('code=the-code', [], $connection)->reason);
        $this->fetcher->assertNothingFetched();
    }

    /**
     * A request that keeps no PKCE verifier is the caller's mistake, and no
     * provider is called.
     *
     * @return void
     */
    public function testNoVerifierIsALogicException(): void
    {
        try {
            $this->complete('code=the-code', ['codeVerifier' => null]);
            self::fail('A request that keeps no verifier must throw.');
        } catch (\LogicException $exception) {
            self::assertSame('An OpenID Connect authorisation request keeps its PKCE verifier.', $exception->getMessage());
        }

        $this->fetcher->assertNothingFetched();
    }

    /**
     * Rows of `[query]`: a response refused before the token request.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideQueriesRefusedBeforeTheTokenRequest(): iterable
    {
        yield from [
            'a repeated parameter' => ['code=a&code=b'],
            'a wrong issuer'       => ['code=a&iss=https%3A%2F%2Fother.example.test'],
            'an error'             => ['error=access_denied'],
            'an error and a code'  => ['error=access_denied&code=a'],
            'neither'              => ['state=a'],
        ];
    }

    /**
     * A response refused before the token request never decrypts the PKCE
     * verifier: a ciphertext no key decrypts does not get in its way.
     *
     * @param  string  $query
     * @return void
     */
    #[DataProvider('provideQueriesRefusedBeforeTheTokenRequest')]
    public function testARefusalBeforeTheTokenRequestNeverDecryptsTheVerifier(string $query): void
    {
        self::assertNotNull($this->complete($query, ['codeVerifier' => 'not-a-ciphertext'])->reason);
    }

    /**
     * A response that reaches the token request decrypts the verifier once, to
     * send it; a ciphertext no key decrypts propagates, and nothing is sent.
     *
     * @return void
     */
    public function testAVerifierNoKeyDecryptsPropagates(): void
    {
        $this->expectException(DecryptException::class);

        try {
            $this->complete('code=the-code', ['codeVerifier' => 'not-a-ciphertext']);
        } finally {
            $this->fetcher->assertNothingFetched();
        }
    }

    /**
     * The verifier is what the form carries, decrypted exactly as stored.
     *
     * @return void
     */
    public function testSendsTheVerifierTheRequestKept(): void
    {
        $this->complete('code=the-code');

        self::assertSame(self::VERIFIER, $this->fetcher->requests()[0]->form()['code_verifier']);
    }

    /**
     * A verified answer goes to the validation, then to the assembly, whose
     * answer is the result.
     *
     * @return void
     */
    public function testATokenResponseGoesOnToTheValidationAndTheAssembly(): void
    {
        $completion = $this->complete('code=the-code');

        self::assertSame($this->answers['completion'], $completion);
        self::assertCount(1, $this->validated);

        $tokens     = $this->validated[0] ?? self::fail('Nothing was validated.');
        $validation = $this->answers['validation'];
        $assembled  = $this->assembled[0] ?? self::fail('Nothing was assembled.');

        self::assertInstanceOf(IdTokenValidation::class, $validation);
        self::assertSame([self::ID_TOKEN, self::ACCESS_TOKEN, 'Bearer'], [$tokens->idToken(), $tokens->accessToken(), $tokens->tokenType]);
        self::assertCount(1, $this->assembled);
        self::assertSame($validation->token, $assembled[0]);
        self::assertSame($tokens, $assembled[1]);
    }

    /**
     * An ID token the validation refuses is refused for its reason, and the
     * claims are never assembled.
     *
     * @return void
     */
    public function testAnIdTokenTheValidationRefusesIsRefusedForItsReason(): void
    {
        $this->answers['validation'] = IdTokenValidation::refused(FailureReason::SIGNATURE_INVALID);

        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->complete('code=the-code')->reason);
        self::assertCount(0, $this->assembled);
    }

    /**
     * Claims the assembly refuses are refused for its reason.
     *
     * @return void
     */
    public function testClaimsTheAssemblyRefusesAreRefusedForItsReason(): void
    {
        $this->answers['completion'] = Completion::refused(FailureReason::USERINFO_INVALID);

        self::assertSame(FailureReason::USERINFO_INVALID, $this->complete('code=the-code')->reason);
    }

    /**
     * Judge the callback.
     *
     * @param  string  $query
     * @param  array{expectedIssuer?: ?string, issuerRequired?: bool, codeVerifier?: ?string}  $consumed
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     *
     * @throws \LogicException
     */
    private function complete(string $query, array $consumed = [], ?Connection $connection = null): Completion
    {
        $connection ??= $this->connection;

        return app(CallbackCompletion::class)->complete(
            $connection,
            OidcOptions::of($connection),
            new CompletionRequest('GET', $query, []),
            $this->consumed($consumed),
            Clients::browser(),
        );
    }

    /**
     * The request the callback answers, with the changes given.
     *
     * @param  array{expectedIssuer?: ?string, issuerRequired?: bool, codeVerifier?: ?string}  $changes
     * @return \SineMacula\Laravel\Sso\Protocols\ConsumedRequest
     */
    private function consumed(array $changes): ConsumedRequest
    {
        $encrypter = app(SecretEncrypter::class);

        return new ConsumedRequest(...[
            'purpose'        => Purpose::SIGN_IN,
            'application'    => 'web',
            'reference'      => RequestReference::fromString(self::REFERENCE),
            'startedAt'      => $this->clock->now(),
            'expectedIssuer' => $this->provider->issuer,
            'issuerRequired' => false,
            'codeVerifier'   => $encrypter->encrypt(self::VERIFIER),
            'encrypter'      => $encrypter,
            ...$changes,
        ]);
    }

    /**
     * An enabled OIDC connection of the provider with a client secret, and the
     * settings given.
     *
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function oidc(array $settings): Connection
    {
        return $this->makeConnection([
            'enabled'  => true,
            'settings' => [...self::settings(), ...$settings],
            'secrets'  => app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret(FakeOpenIdProvider::CLIENT_SECRET)]),
        ]);
    }

    /**
     * The fake provider's settings.
     *
     * @return array<string, string>
     */
    private static function settings(): array
    {
        return [
            'issuer'                 => FakeOpenIdProvider::ISSUER,
            'authorization_endpoint' => FakeOpenIdProvider::ISSUER . '/authorize',
            'token_endpoint'         => FakeOpenIdProvider::ISSUER . '/token',
            'jwks_uri'               => FakeOpenIdProvider::ISSUER . '/jwks',
            'client_id'              => FakeOpenIdProvider::CLIENT_ID,
        ];
    }

    /**
     * Bind doubles of the ID token's validation and the claims' assembly, each
     * recording what it is given and answering as the test sets.
     *
     * @return void
     */
    private function bindDoubles(): void
    {
        $this->app?->instance(IdTokenValidator::class, new readonly class ($this->validated, $this->answers) extends IdTokenValidator {
            /**
             * Constructor.
             *
             * @param  \ArrayObject<int, \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse>  $seen
             * @param  \ArrayObject<string, mixed>  $answers
             *
             * @phpstan-ignore constructor.missingParentCall
             */
            public function __construct(

                /** What it was given. */
                private \ArrayObject $seen,

                /** What it answers. */
                private \ArrayObject $answers,
            ) {}

            /**
             * Record the tokens and answer as set.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
             * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse  $tokens
             * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
             * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
             * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation
             */
            #[\Override]
            public function validate(SsoConnection $connection, OidcOptions $options, TokenResponse $tokens, ConsumedRequest $consumed, ClientContext $client): IdTokenValidation
            {
                unset($connection, $options, $consumed);

                $this->seen->append($tokens);

                /** @var \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation */
                return $this->answers['validation'];
            }
        });

        $this->app?->instance(ClaimsAssembler::class, new readonly class ($this->assembled, $this->answers) extends ClaimsAssembler {
            /**
             * Constructor.
             *
             * @param  \ArrayObject<int, array{\SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken, \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse}>  $seen
             * @param  \ArrayObject<string, mixed>  $answers
             *
             * @phpstan-ignore constructor.missingParentCall
             */
            public function __construct(

                /** What it was given. */
                private \ArrayObject $seen,

                /** What it answers. */
                private \ArrayObject $answers,
            ) {}

            /**
             * Record the token and the tokens, and answer as set.
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
                unset($connection, $options, $consumed);

                $this->seen->append([$idToken, $tokens]);

                /** @var \SineMacula\Laravel\Sso\Protocols\Completion */
                return $this->answers['completion'];
            }
        });
    }

    /**
     * The provider's key, made once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(): FakeSigningKey
    {
        return self::$key ??= FakeSigningKey::rsa();
    }
}
