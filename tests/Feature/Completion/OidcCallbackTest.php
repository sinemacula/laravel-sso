<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
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
use SineMacula\Laravel\Sso\Protocols\Oidc\TokenResponseReader;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\DumpsValues;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\TestCase;

/**
 * The OpenID Connect callback through the public helper, with hostile input
 * (SSO-5.4, SSO-5.5, SSO-5.7, SSO-7.1, SSO-7.2, SSO-7.6, SSO-11.4), against the
 * fake provider on the fake fetcher and doubles of the ID token's validation
 * and the claims' assembly: every refused query is `request_unknown`, reported
 * once and consuming nothing; the caps at, under and over; `iss` and the mix-up
 * defence; errors; every token endpoint answer; each client authentication at
 * the provider's strict endpoint; the exact form; a request staying consumed
 * whatever happens; and no provider token or description in any event, log or
 * dump.
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
#[CoversClass(TokenResponseReader::class)]
final class OidcCallbackTest extends TestCase
{
    use CapturesLogs, DumpsValues, RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The `web` application's redirect URI. */
    private const string REDIRECT_URI = 'https://app.example.com/sso';

    /** @var string The `admin` application's redirect URI. */
    private const string ADMIN_REDIRECT_URI = 'https://admin.example.com/sso';

    /** @var string The other provider's issuer. */
    private const string OTHER_ISSUER = 'https://other-op.example.test';

    /** @var string What a provider's `error_description` holds, never logged. */
    private const string DESCRIPTION = 'description-never-reported';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The key the providers sign with, made once. */
    private static ?FakeSigningKey $signingKey = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The connection's client assertion key, made once. */
    private static ?FakeSigningKey $clientKey = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher every provider answers on. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider of the connection. */
    private FakeOpenIdProvider $provider;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection, authenticating by `client_secret_basic`. */
    private Connection $connection;

    /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse> What the validation double was given. */
    private \ArrayObject $validated;

    /** @var array<string, string> What each request was started with, by `state` and `verifier` of the latest. */
    private array $started = [];

    /**
     * Bind a fixed clock, the fake fetcher, the recording issuer, the doubles
     * and a request from an IP address, configure the endpoints and the
     * applications, create the tables and the connection, serve the provider,
     * capture logs and record events.
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

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Fetcher::class, $this->fetcher);
        $this->app?->instance(HandoffIssuer::class, new RecordingHandoffIssuer);
        $this->app?->instance('request', Request::create('https://evil.example.test/auth/sso/connections/x/callback', 'GET', server: ['REMOTE_ADDR' => '203.0.113.7']));

        $this->bindDoubles();

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', [
            'web'   => ['redirect_uri' => self::REDIRECT_URI, 'external_sign_in' => true, 'unlinked_handoffs' => true],
            'admin' => ['redirect_uri' => self::ADMIN_REDIRECT_URI, 'external_sign_in' => true, 'unlinked_handoffs' => true],
        ]);

        $this->usePackageTables();

        $this->provider   = $this->provider(FakeOpenIdProvider::ISSUER);
        $this->connection = $this->connectionOf($this->provider);

        $this->captureLogs();
        $this->startRecordingEvents();
    }

    /**
     * A sign-in completes: the code is exchanged at the provider's strict
     * endpoint, its tokens reach the validation, and it reports
     * `ResultVerified` then `HandoffIssued`, with the request consumed and
     * completed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACallbackCompletes(): void
    {
        $authorization = $this->authorization();
        $request       = $this->latestRequest();
        $result        = $this->receiveCallback($authorization->query());

        self::assertSame(['completed', null, self::REDIRECT_URI, $request->reference], [$result->status->value, $result->reason, $result->redirectUri, $result->reference?->value]);
        $this->assertEventSequence([ResultVerified::class, ResultUnlinked::class, HandoffIssued::class]);
        $this->assertNoFailure();
        self::assertCount(1, $this->tokenRequests());
        self::assertCount(1, $this->validated);
        self::assertSame([(string) $authorization->idToken, $authorization->accessToken], [$this->validatedTokens()->idToken(), $this->validatedTokens()->accessToken()]);

        $row = $request->fresh();

        self::assertNotNull($row?->consumed_at);
        self::assertNotNull($row->completed_at);
    }

    /**
     * Rows of `[query]`: what a callback's query is refused for, built from the
     * authorisation it answers.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization): string}>
     */
    public static function provideRefusedQueries(): iterable
    {
        yield from [
            'a repeated state' => [static fn (FakeAuthorization $grant): string => FakeAuthorization::repeated([
                ['code', $grant->code], ['state', (string) $grant->parameter('state')], ['state', (string) $grant->parameter('state')], ['iss', $grant->issuer],
            ])],
            'a repeated code' => [static fn (FakeAuthorization $grant): string => FakeAuthorization::repeated([
                ['code', $grant->code], ['code', $grant->code], ['state', (string) $grant->parameter('state')], ['iss', $grant->issuer],
            ])],
            'a repeated iss' => [static fn (FakeAuthorization $grant): string => FakeAuthorization::repeated([
                ['code', $grant->code], ['state', (string) $grant->parameter('state')], ['iss', $grant->issuer], ['iss', $grant->issuer],
            ])],
            'a conflicting state' => [static fn (FakeAuthorization $grant): string => FakeAuthorization::repeated([
                ['code', $grant->code], ['state', str_repeat('A', 43)], ['state', (string) $grant->parameter('state')], ['iss', $grant->issuer],
            ])],
            'a conflicting code' => [static fn (FakeAuthorization $grant): string => FakeAuthorization::repeated([
                ['code', 'another-code'], ['code', $grant->code], ['state', (string) $grant->parameter('state')], ['iss', $grant->issuer],
            ])],
            'a conflicting iss' => [static fn (FakeAuthorization $grant): string => FakeAuthorization::repeated([
                ['code', $grant->code], ['state', (string) $grant->parameter('state')], ['iss', self::OTHER_ISSUER], ['iss', $grant->issuer],
            ])],
            'a repeat once decoded' => [static fn (FakeAuthorization $grant): string => 'st%61te=' . $grant->parameter('state') . '&' . $grant->query()],
            'an array state'        => [static fn (FakeAuthorization $grant): string => FakeAuthorization::repeated([
                ['code', $grant->code], ['state[]', (string) $grant->parameter('state')], ['iss', $grant->issuer],
            ])],
            'a raw array state' => [static fn (FakeAuthorization $grant): string => 'code=' . $grant->code . '&state[]=' . $grant->parameter('state')],
            'a keyed code'      => [static fn (FakeAuthorization $grant): string => FakeAuthorization::repeated([
                ['code[x]', $grant->code], ['state', (string) $grant->parameter('state')], ['iss', $grant->issuer],
            ])],
            'a name over the cap'    => [static fn (FakeAuthorization $grant): string => $grant->query() . '&' . str_repeat('n', 2049) . '=a'],
            'a value over the cap'   => [static fn (FakeAuthorization $grant): string => $grant->query() . '&extra=' . str_repeat('x', 2049)],
            'a code over the cap'    => [static fn (FakeAuthorization $grant): string => $grant->query(['code' => str_repeat('x', 2049)])],
            'a query over the cap'   => [static fn (FakeAuthorization $grant): string => self::paddedTo($grant->query(), 8193)],
            'too many parameters'    => [static fn (FakeAuthorization $grant): string => self::withParameters($grant->query(), 14)],
            'a control character'    => [static fn (FakeAuthorization $grant): string => $grant->query() . '&extra=a%00b'],
            'invalid UTF-8'          => [static fn (FakeAuthorization $grant): string => $grant->query() . '&extra=a%FFb'],
            'no state'               => [static fn (FakeAuthorization $grant): string => $grant->query(['state' => null])],
            'an error with no state' => [static fn (FakeAuthorization $grant): string => $grant->errorQuery('access_denied', null, ['state' => null])],
        ];
    }

    /**
     * A query the callback refuses is `request_unknown`, with exactly one
     * `FlowFailed` that names no request, nothing consumed, no provider called
     * and no redirect target.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization): string  $query
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideRefusedQueries')]
    public function testARefusedQueryIsRequestUnknown(\Closure $query): void
    {
        $authorization = $this->authorization();

        $this->assertRequestUnknown($this->receiveCallback($query($authorization)), $this->latestRequest());
    }

    /**
     * Rows of `[query]`: a query at or under each cap, which is not refused.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization): string}>
     */
    public static function provideQueriesWithinTheCaps(): iterable
    {
        yield from [
            'a name under the cap'  => [static fn (FakeAuthorization $grant): string => $grant->query() . '&' . str_repeat('n', 2047) . '=a'],
            'a name at the cap'     => [static fn (FakeAuthorization $grant): string => $grant->query() . '&' . str_repeat('n', 2048) . '=a'],
            'a value under the cap' => [static fn (FakeAuthorization $grant): string => $grant->query() . '&extra=' . str_repeat('x', 2047)],
            'a value at the cap'    => [static fn (FakeAuthorization $grant): string => $grant->query() . '&extra=' . str_repeat('x', 2048)],
            'a query under the cap' => [static fn (FakeAuthorization $grant): string => self::paddedTo($grant->query(), 8191)],
            'a query at the cap'    => [static fn (FakeAuthorization $grant): string => self::paddedTo($grant->query(), 8192)],
            'parameters under'      => [static fn (FakeAuthorization $grant): string => self::withParameters($grant->query(), 12)],
            'parameters at the cap' => [static fn (FakeAuthorization $grant): string => self::withParameters($grant->query(), 13)],
            'a name it ignores'     => [static fn (FakeAuthorization $grant): string => $grant->query() . '&State=other&session_state=other'],
        ];
    }

    /**
     * A query at or under each cap completes, whatever else it carries.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization): string  $query
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideQueriesWithinTheCaps')]
    public function testAQueryWithinTheCapsCompletes(\Closure $query): void
    {
        $authorization = $this->authorization();

        self::assertTrue($this->receiveCallback($query($authorization))->isCompleted());
        self::assertCount(1, $this->tokenRequests());
    }

    /**
     * Rows of `[state]`: a state not of the package's shape.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedStates(): iterable
    {
        yield from [
            '42 characters'                 => [str_repeat('A', 42)],
            '44 characters'                 => [str_repeat('A', 44)],
            'padded to 43'                  => [str_repeat('A', 42) . '='],
            'padded past 43'                => [str_repeat('A', 43) . '='],
            'a character outside base64url' => ['+' . str_repeat('A', 42)],
        ];
    }

    /**
     * A state not of the package's shape is `request_unknown` before any
     * lookup, even when a request stored its digest, which stays unconsumed.
     *
     * @param  string  $state
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideMalformedStates')]
    public function testAMalformedStateIsRequestUnknown(string $state): void
    {
        $authorization = $this->authorization(['state_digest' => hash('sha256', $state)]);

        $this->assertRequestUnknown($this->receiveCallback($authorization->query(['state' => $state])), $this->latestRequest());
    }

    /**
     * A state no request has is `request_unknown`, with nothing to consume.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAStateNoRequestHasIsRequestUnknown(): void
    {
        $authorization = $this->authorization();

        $this->assertRequestUnknown($this->receiveCallback($authorization->query(['state' => str_repeat('A', 43)])), $this->latestRequest());
    }

    /**
     * Rows of `[iss, required, reason]`: what arrives as `iss`, whether the
     * request requires it, and the reason it is refused for, if any.
     *
     * @return iterable<string, array{0: ?string, 1: bool, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideIssuers(): iterable
    {
        $issuer   = FakeOpenIdProvider::ISSUER;
        $mismatch = FailureReason::ISSUER_MISMATCH;

        yield from [
            'absent and not required'     => [null, false, null],
            'absent and required'         => [null, true, $mismatch],
            'present and equal'           => [$issuer, false, null],
            'present, equal and required' => [$issuer, true, null],
            'another provider'            => [self::OTHER_ISSUER, false, $mismatch],
            'a trailing slash'            => [$issuer . '/', false, $mismatch],
            'another case'                => [strtoupper($issuer), false, $mismatch],
            'present, wrong and required' => [self::OTHER_ISSUER, true, $mismatch],
        ];
    }

    /**
     * `iss` is held to the issuer the request pinned, and to the request saying
     * it must be there: refused with `issuer_mismatch`, one `FlowFailed` with
     * the request's reference, no token request and the request consumed.
     *
     * @param  ?string  $iss
     * @param  bool  $required
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideIssuers')]
    public function testHoldsTheIssuerToTheRequest(?string $iss, bool $required, ?FailureReason $reason): void
    {
        $authorization = $this->authorization(['issuer_required' => $required]);
        $result        = $this->receiveCallback($authorization->query(['iss' => $iss]));

        if ($reason === null) {
            self::assertTrue($result->isCompleted());
            $this->assertEventSequence([ResultVerified::class, ResultUnlinked::class, HandoffIssued::class]);

            return;
        }

        $this->assertRefused($result, $reason, $this->latestRequest());
        self::assertSame([], $this->tokenRequests());
    }

    /**
     * Mix-up: provider A's code and state sent to provider B's callback find
     * A's request through another connection, so `connection_mismatch`, sent to
     * A's request's application; neither provider is asked for a token.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACallbackAtAnotherConnectionIsAConnectionMismatch(): void
    {
        $other         = $this->provider(self::OTHER_ISSUER);
        $otherConn     = $this->connectionOf($other);
        $authorization = $this->authorization(['application' => 'admin']);
        $request       = $this->latestRequest();
        $result        = $this->receiveCallback($authorization->query(), $otherConn);

        self::assertSame(
            ['failed', FailureReason::CONNECTION_MISMATCH, self::ADMIN_REDIRECT_URI, $request->reference],
            [$result->status->value, $result->reason, $result->redirectUri, $result->reference?->value],
        );
        $this->assertEventSequence([FlowFailed::class]);
        self::assertSame($request->reference, $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::CONNECTION_MISMATCH)->context()->requestReference);
        self::assertSame([], $this->fetcher->requests());
        self::assertNotNull($request->fresh()?->consumed_at);
    }

    /**
     * Mix-up without `iss` is refused the same way: the response is accepted
     * only at the callback of the request's own connection.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACallbackAtAnotherConnectionWithoutAnIssuerIsAConnectionMismatch(): void
    {
        $other         = $this->provider(self::OTHER_ISSUER);
        $authorization = $this->authorization();
        $result        = $this->receiveCallback($authorization->query(['iss' => null]), $this->connectionOf($other));

        self::assertSame(FailureReason::CONNECTION_MISMATCH, $result->reason);
        self::assertSame([], $this->fetcher->requests());
    }

    /**
     * Mix-up: provider B's `iss` on a callback of A's connection is
     * `issuer_mismatch`, with no token request to either provider.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnotherProvidersIssuerIsAnIssuerMismatch(): void
    {
        $this->provider(self::OTHER_ISSUER);

        $authorization = $this->authorization();

        $this->assertRefused($this->receiveCallback($authorization->query(['iss' => self::OTHER_ISSUER])), FailureReason::ISSUER_MISMATCH, $this->latestRequest());
        self::assertSame([], $this->fetcher->requests());
    }

    /**
     * Rows of `[query, reason]`: a response refused for its `error` and `code`.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization): string, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideErrorResponses(): iterable
    {
        yield from [
            'an error and a code' => [static fn (FakeAuthorization $grant): string => $grant->query(['error' => 'access_denied']), FailureReason::RESPONSE_INVALID],
            'neither'             => [static fn (FakeAuthorization $grant): string => $grant->query(['code' => null]), FailureReason::RESPONSE_INVALID],
            'an empty code'       => [static fn (FakeAuthorization $grant): string => $grant->query(['code' => '']), FailureReason::RESPONSE_INVALID],
            'an error alone'      => [static fn (FakeAuthorization $grant): string => $grant->errorQuery('access_denied', self::DESCRIPTION), FailureReason::PROVIDER_ERROR],
        ];
    }

    /**
     * Each is refused for its reason, with one `FlowFailed`, the request
     * consumed, no token request and no description anywhere.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization): string  $query
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideErrorResponses')]
    public function testAnErrorOrCodeResponseIsRefused(\Closure $query, FailureReason $reason): void
    {
        $authorization = $this->authorization();

        $this->assertRefused($this->receiveCallback($query($authorization)), $reason, $this->latestRequest());
        self::assertSame([], $this->tokenRequests());
        $this->assertNothingReported([self::DESCRIPTION]);
    }

    /**
     * An error alone is logged by its code, and the failure names only the
     * reason.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnErrorIsLoggedByItsCode(): void
    {
        $authorization = $this->authorization();

        $this->receiveCallback($authorization->errorQuery('access_denied', self::DESCRIPTION));

        self::assertSame(['sso.oidc.callback_error'], array_column($this->capturedLogRecords(), 'message'));
        $this->assertLoggedContains('access_denied');
    }

    /**
     * Rows of `[answer, reason]`: what the token endpoint answers, and the
     * completion's reason.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchResult, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideTokenAnswers(): iterable
    {
        $tokens  = ['id_token' => 'a.b.c', 'access_token' => 'an-access-token', 'token_type' => 'Bearer'];
        $invalid = FailureReason::TOKEN_RESPONSE_INVALID;

        yield from [
            'invalid_grant'      => [FakeTokenEndpoint::json(400, ['error' => 'invalid_grant', 'error_description' => self::DESCRIPTION]), FailureReason::PROVIDER_ERROR],
            'a server error'     => [FakeTokenEndpoint::json(500, ['error' => 'server_error', 'error_description' => self::DESCRIPTION]), FailureReason::FETCH_FAILED],
            'a redirect'         => [FetchResult::fetched(302, ['Location' => 'https://elsewhere.example.test'], ''), FailureReason::FETCH_FAILED],
            'a timeout'          => [FetchResult::failed(), FailureReason::FETCH_FAILED],
            'a refused request'  => [FetchResult::refused(), FailureReason::FETCH_REFUSED],
            'a non-JSON body'    => [FetchResult::fetched(200, [], 'id_token=a.b.c'), $invalid],
            'duplicate members'  => [FetchResult::fetched(200, [], '{"id_token":"a.b.c","id_token":"d.e.f","access_token":"a","token_type":"Bearer"}'), $invalid],
            'no access token'    => [FakeTokenEndpoint::json(200, array_diff_key($tokens, ['access_token' => 1])), $invalid],
            'the token type mac' => [FakeTokenEndpoint::json(200, [...$tokens, 'token_type' => 'mac']), $invalid],
            'no ID token'        => [FakeTokenEndpoint::json(200, array_diff_key($tokens, ['id_token' => 1])), FailureReason::ID_TOKEN_INVALID],
            'an empty ID token'  => [FakeTokenEndpoint::json(200, [...$tokens, 'id_token' => '']), FailureReason::ID_TOKEN_INVALID],
            'a numeric ID token' => [FakeTokenEndpoint::json(200, [...$tokens, 'id_token' => 7]), FailureReason::ID_TOKEN_INVALID],
        ];
    }

    /**
     * Each answer refuses the completion for its exact reason after exactly one
     * token request, never retried, with one `FlowFailed`, the request consumed
     * and the validation never asked. Submitting the callback again finds the
     * request consumed: `request_unknown`, with no second token request.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $answer
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideTokenAnswers')]
    public function testEachTokenAnswerRefusesForItsReason(FetchResult $answer, FailureReason $reason): void
    {
        $this->provider->respond('token', $answer);

        $authorization = $this->authorization();

        $this->assertRefused($this->receiveCallback($authorization->query()), $reason, $this->latestRequest());
        self::assertCount(1, $this->tokenRequests());
        self::assertCount(0, $this->validated);
        $this->assertNothingReported([self::DESCRIPTION]);

        $again = $this->receiveCallback($authorization->query());

        self::assertSame([true, FailureReason::REQUEST_UNKNOWN], [$again->isRejected(), $again->reason]);
        self::assertCount(1, $this->tokenRequests());
    }

    /**
     * A code the provider's strict endpoint refuses (its verifier does not
     * match) is `provider_error`, logged by its code.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACodeTheProviderRefusesIsAProviderError(): void
    {
        $authorization = $this->authorization(['code_verifier' => app(SecretEncrypter::class)->encrypt('another-verifier-than-the-challenge-names-1')]);

        $this->assertRefused($this->receiveCallback($authorization->query()), FailureReason::PROVIDER_ERROR, $this->latestRequest());
        self::assertSame(['sso.oidc.token_error'], array_column($this->capturedLogRecords(), 'message'));
        $this->assertLoggedContains('invalid_grant');
        $this->assertNothingLoggedContains('redirect_uri or code_verifier');
    }

    /**
     * Rows of `[method, kind]`: a client authentication by a client secret, and
     * the credential that carries it.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind}>
     */
    public static function provideSecretMethods(): iterable
    {
        yield from [
            'client_secret_basic' => ['client_secret_basic', CredentialKind::CLIENT_SECRET_BASIC],
            'client_secret_post'  => ['client_secret_post', CredentialKind::CLIENT_SECRET_POST],
        ];
    }

    /**
     * The provider's strict endpoint accepts each client secret method.
     *
     * @param  string  $method
     * @param  \SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind  $kind
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideSecretMethods')]
    public function testTheProviderAcceptsEachClientSecretMethod(string $method, CredentialKind $kind): void
    {
        $this->provider->register(FakeOpenIdProvider::CLIENT_ID, $method, FakeOpenIdProvider::CLIENT_SECRET);

        $connection    = $this->connectionOf($this->provider, ['client_authentication' => $method]);
        $authorization = $this->authorization(connection: $connection);
        $result        = $this->receiveCallback($authorization->query(), $connection);

        self::assertTrue($result->isCompleted());
        self::assertSame($kind, $this->tokenRequests()[0]->credentials?->kind);
        self::assertSame($authorization->accessToken, $this->validatedTokens()->accessToken());
    }

    /**
     * The provider's strict endpoint accepts the package's client assertion,
     * verifying it with the connection's public key.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheProviderAcceptsAClientAssertion(): void
    {
        $this->provider->register(FakeOpenIdProvider::CLIENT_ID, 'private_key_jwt', null, self::clientSigningKey()->publicKeyPem);

        $connection = $this->connectionOf($this->provider, ['client_authentication' => 'private_key_jwt'], null);

        $this->clientKey($connection);

        $authorization = $this->authorization(connection: $connection);
        $result        = $this->receiveCallback($authorization->query(), $connection);

        self::assertTrue($result->isCompleted());
        self::assertSame(CredentialKind::PRIVATE_KEY_JWT, $this->tokenRequests()[0]->credentials?->kind);
        self::assertSame($authorization->accessToken, $this->validatedTokens()->accessToken());
    }

    /**
     * A wrong client secret is `invalid_client`: `provider_error`, logged by
     * its code, with neither secret logged.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAWrongSecretIsAProviderError(): void
    {
        $connection    = $this->connectionOf($this->provider, secret: 'the-wrong-client-secret');
        $authorization = $this->authorization(connection: $connection);
        $request       = $this->latestRequest();

        $this->assertRefused($this->receiveCallback($authorization->query(), $connection), FailureReason::PROVIDER_ERROR, $request);
        $this->assertLoggedContains('invalid_client');
        $this->assertNothingLoggedContains('the-wrong-client-secret', FakeOpenIdProvider::CLIENT_SECRET);
    }

    /**
     * The token request carries exactly the form: the `redirect_uri` the
     * authorisation request named, which is the configured callback and never
     * the host of the request being served, and the PKCE verifier; and it is
     * held to the token request's timeout and cap.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testSendsExactlyTheForm(): void
    {
        $authorization = $this->authorization();

        $this->receiveCallback($authorization->query());

        $request  = $this->tokenRequests()[0];
        $callback = 'https://sp.example.test/auth/sso/connections/' . $this->connection->id . '/callback';

        self::assertSame($callback, $authorization->parameter('redirect_uri'));
        self::assertSame([
            'grant_type'    => 'authorization_code',
            'code'          => $authorization->code,
            'redirect_uri'  => $callback,
            'code_verifier' => $this->started['verifier'],
        ], $request->form());
        self::assertSame(['POST', $this->provider->endpoint('token'), 10, 65536], [$request->method(), $request->url, $request->timeoutSeconds, $request->maxBytes]);
    }

    /**
     * No access, refresh or ID token, code, state, nonce, verifier, client
     * secret or description reaches any event, log, dump of an event or dump of
     * a result, across a sign-in, an error response and an error from the token
     * endpoint; the request is named only by its reference.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testNoProviderValueReachesAnEventOrLog(): void
    {
        $signedIn = $this->authorization();
        $needles  = [
            (string) $signedIn->idToken,
            $signedIn->accessToken,
            'fake-refresh-' . $signedIn->code,
            $signedIn->code,
            (string) $signedIn->parameter('state'),
            (string) $signedIn->parameter('nonce'),
            $this->started['verifier'],
            FakeOpenIdProvider::CLIENT_SECRET,
            self::DESCRIPTION,
        ];

        $results = [$this->receiveCallback($signedIn->query())];

        $denied  = $this->authorization();
        $needles = [...$needles, (string) $denied->parameter('state'), (string) $denied->parameter('nonce')];

        $results[] = $this->receiveCallback($denied->errorQuery('access_denied', self::DESCRIPTION));

        $this->provider->respond('token', FakeTokenEndpoint::json(400, ['error' => 'invalid_grant', 'error_description' => self::DESCRIPTION]));

        $refused = $this->authorization();
        $needles = [...$needles, $refused->code, (string) $refused->parameter('state'), $this->started['verifier']];

        $results[] = $this->receiveCallback($refused->query());

        self::assertSame(['completed', 'failed', 'failed'], array_map(static fn (CompletionResult $result): string => $result->status->value, $results));
        self::assertNotSame([], $this->capturedLogRecords());

        $this->assertNothingReported($needles);

        foreach (self::dumps($results) as $dump) {
            foreach ($needles as $needle) {
                self::assertStringNotContainsString($needle, $dump);
            }
        }
    }

    /**
     * A request a trust change overtook is `connection_unavailable` at its
     * consumption: no provider is called.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARequestOfAnotherTrustVersionCallsNoProvider(): void
    {
        $authorization = $this->authorization(['trust_version' => $this->connection->trust_version + 1]);

        $this->assertRefused($this->receiveCallback($authorization->query()), FailureReason::CONNECTION_UNAVAILABLE, $this->latestRequest());
        self::assertSame([], $this->fetcher->requests());
    }

    /**
     * A connection no longer usable (its secret removed since the start) is
     * `connection_unavailable`, its request consumed, and no provider is
     * called.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAConnectionNoLongerUsableCallsNoProvider(): void
    {
        $authorization = $this->authorization();

        $this->connection->forceFill(['secrets' => null])->save();

        $this->assertRefused($this->receiveCallback($authorization->query()), FailureReason::CONNECTION_UNAVAILABLE, $this->latestRequest());
        self::assertSame([], $this->fetcher->requests());
    }

    /**
     * The validation's refusal is the completion's, and the claims' assembly is
     * never asked.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnIdTokenRefusedIsReported(): void
    {
        $this->app?->instance(IdTokenValidator::class, new readonly class extends IdTokenValidator {
            /**
             * Constructor: it needs none of what the real validation needs.
             *
             * @phpstan-ignore constructor.missingParentCall
             */
            public function __construct() {}

            /**
             * Refuse the token.
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
                unset($connection, $options, $tokens, $consumed);

                return IdTokenValidation::refused(FailureReason::NONCE_MISMATCH);
            }
        });

        $authorization = $this->authorization();

        $this->assertRefused($this->receiveCallback($authorization->query()), FailureReason::NONCE_MISMATCH, $this->latestRequest());
    }

    /**
     * A callback inside a transaction open on the storage connection is refused
     * before anything is written or sent, so the token request is never inside
     * one.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACallbackInsideATransactionIsRefused(): void
    {
        $authorization = $this->authorization();
        $database      = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        try {
            $this->receiveCallback($authorization->query());
            self::fail('A callback inside a transaction must throw.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString('outside any transaction', $exception->getMessage());
        } finally {
            $database->rollBack();
        }

        self::assertSame([], $this->fetcher->requests());
        self::assertNull($this->latestRequest()->fresh()?->consumed_at);
    }

    /**
     * A PKCE verifier no key decrypts is not read for a response refused before
     * the token request.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAVerifierNoKeyDecryptsIsNotReadForAResponseRefusedFirst(): void
    {
        $authorization = $this->authorization(['code_verifier' => 'not-a-ciphertext']);

        $this->assertRefused($this->receiveCallback($authorization->errorQuery('access_denied')), FailureReason::PROVIDER_ERROR, $this->latestRequest());
    }

    /**
     * A PKCE verifier no key decrypts, once the token request needs it, is a
     * server error and never a failed sign-in: it propagates, with the request
     * consumed, no token request and no failure reported (SSO-11.4).
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAVerifierNoKeyDecryptsIsAServerError(): void
    {
        $authorization = $this->authorization(['code_verifier' => 'not-a-ciphertext']);

        try {
            $this->receiveCallback($authorization->query());
            self::fail('A verifier no key decrypts must propagate.');
        } catch (DecryptException) {
            self::assertSame([], $this->fetcher->requests());
            $this->assertNoFailure();
            self::assertNotNull($this->latestRequest()->fresh()?->consumed_at);
        }
    }

    /**
     * Assert the callback was refused with no redirect target: exactly one
     * `FlowFailed(callback, request_unknown)`, naming no request, with the
     * request unconsumed and no provider called.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @return void
     */
    private function assertRequestUnknown(CompletionResult $result, AuthorizationRequest $request): void
    {
        self::assertSame(['rejected', FailureReason::REQUEST_UNKNOWN, null, null], [$result->status->value, $result->reason, $result->redirectUri, $result->reference]);
        $this->assertEventSequence([FlowFailed::class]);
        self::assertNull($this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::REQUEST_UNKNOWN)->context()->requestReference);
        self::assertNull($request->fresh()?->consumed_at);
        self::assertSame([], $this->fetcher->requests());
    }

    /**
     * Assert the callback failed for the reason, redirected to the `web`
     * application: exactly one `FlowFailed(callback, reason)`, with the
     * request's reference, and the request consumed and finished.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @return void
     */
    private function assertRefused(CompletionResult $result, FailureReason $reason, AuthorizationRequest $request): void
    {
        self::assertSame(
            ['failed', $reason, self::REDIRECT_URI, $request->reference],
            [$result->status->value, $result->reason, $result->redirectUri, $result->reference?->value],
        );
        $this->assertEventSequence([FlowFailed::class]);
        self::assertSame($request->reference, $this->assertExactlyOneFailure(Flow::CALLBACK, $reason)->context()->requestReference);

        $row = $request->fresh();

        self::assertNotNull($row?->consumed_at);
        self::assertNotNull($row->completed_at);
    }

    /**
     * Assert no recorded event, as dumped any way or encoded as JSON, contains
     * any of the needles.
     *
     * @param  list<string>  $needles
     * @return void
     */
    private function assertNothingReported(array $needles): void
    {
        $events = $this->recordedEvents();
        $texts  = [...array_values(self::dumps($events)), (string) json_encode($events, JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR)];

        foreach ($needles as $needle) {
            foreach ($texts as $text) {
                self::assertStringNotContainsString($needle, $text);
            }
        }

        $this->assertNothingLoggedContains(...$needles);
    }

    /**
     * The tokens the validator was first given.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse
     */
    private function validatedTokens(): TokenResponse
    {
        return $this->validated[0] ?? self::fail('Nothing was validated.');
    }

    /**
     * Complete at the callback of the connection with the query.
     *
     * @param  string  $query
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     * @throws \LogicException
     */
    private function receiveCallback(string $query, ?Connection $connection = null): CompletionResult
    {
        return app(CompletionService::class)->complete(
            CompletionEndpoint::CALLBACK,
            ($connection ?? $this->connection)->id,
            new CompletionRequest('GET', $query, []),
            Clients::browser(),
        );
    }

    /**
     * The token requests made, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Fetching\FetchRequest>
     */
    private function tokenRequests(): array
    {
        return array_values(array_filter($this->fetcher->requests(), static fn (FetchRequest $request): bool => $request->purpose === FetchPurpose::TOKEN));
    }

    /**
     * Store the request a sign-in through the connection started, and have its
     * provider grant it, as its authorisation endpoint would; the attributes
     * given override what the request stored.
     *
     * @param  array<string, mixed>  $attributes
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization
     *
     * @throws \Random\RandomException
     */
    private function authorization(array $attributes = [], ?Connection $connection = null): FakeAuthorization
    {
        $connection ??= $this->connection;
        $state    = self::randomValue();
        $nonce    = self::randomValue();
        $verifier = self::randomValue();

        $this->started = ['verifier' => $verifier];

        $this->makeAuthorizationRequest($connection, $attributes + [
            'state_digest'    => hash('sha256', $state),
            'nonce_digest'    => hash('sha256', $nonce),
            'code_verifier'   => app(SecretEncrypter::class)->encrypt($verifier),
            'expected_issuer' => $this->provider->issuer,
        ]);

        return $this->provider->authorize($this->provider->endpoint('authorization') . '?' . http_build_query([
            'response_type'         => 'code',
            'client_id'             => FakeOpenIdProvider::CLIENT_ID,
            'redirect_uri'          => app(EndpointResolver::class)->endpoints($connection)->callback,
            'scope'                 => 'openid email',
            'state'                 => $state,
            'nonce'                 => $nonce,
            'code_challenge'        => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ]));
    }

    /**
     * The request stored last.
     *
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function latestRequest(): AuthorizationRequest
    {
        return AuthorizationRequest::query()->latest('id')->firstOrFail();
    }

    /**
     * A provider of the issuer, answering on the fetcher.
     *
     * @param  string  $issuer
     * @return \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider
     */
    private function provider(string $issuer): FakeOpenIdProvider
    {
        return (new FakeOpenIdProvider($issuer, self::signingKey(), $this->clock))->serve($this->fetcher);
    }

    /**
     * An enabled connection of the provider, with the settings and the client
     * secret given.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @param  array<string, mixed>  $settings
     * @param  ?string  $secret
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connectionOf(FakeOpenIdProvider $provider, array $settings = [], ?string $secret = FakeOpenIdProvider::CLIENT_SECRET): Connection
    {
        return $this->makeConnection([
            'enabled'  => true,
            'secrets'  => $secret === null ? null : app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret($secret)]),
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
     * Store the connection's current client assertion key.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     */
    private function clientKey(Connection $connection): void
    {
        $key = self::clientSigningKey();

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
     * Bind doubles of the ID token's validation, which records the tokens it is
     * given and validates them, and of the claims' assembly, which verifies.
     *
     * @return void
     */
    private function bindDoubles(): void
    {
        $this->app?->instance(IdTokenValidator::class, new readonly class ($this->validated) extends IdTokenValidator {
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
             * Record the tokens and validate them.
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
                unset($connection, $consumed);

                $this->seen->append($tokens);

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

    /**
     * The query with extra parameters, so it is exactly the bytes given.
     *
     * @param  string  $query
     * @param  int  $bytes
     * @return string
     */
    private static function paddedTo(string $query, int $bytes): string
    {
        $values = $bytes - strlen($query) - 16;
        $each   = (int) floor($values / 4);

        return $query
            . '&p0=' . str_repeat('x', $values - 3 * $each)
            . '&p1=' . str_repeat('x', $each)
            . '&p2=' . str_repeat('x', $each)
            . '&p3=' . str_repeat('x', $each);
    }

    /**
     * The query with this many more parameters.
     *
     * @param  string  $query
     * @param  int  $count
     * @return string
     */
    private static function withParameters(string $query, int $count): string
    {
        return $query . implode('', array_map(static fn (int $index): string => '&p' . $index . '=1', range(1, $count)));
    }

    /**
     * A fresh 256-bit base64url value, as the package's state, nonce and PKCE
     * verifier are.
     *
     * @return string
     *
     * @throws \Random\RandomException
     */
    private static function randomValue(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /**
     * The key the providers sign with, made once for the class.
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
    private static function clientSigningKey(): FakeSigningKey
    {
        return self::$clientKey ??= FakeSigningKey::ec('client-assertion-key');
    }
}
