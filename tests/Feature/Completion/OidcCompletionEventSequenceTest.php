<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionEvents;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\JwksRefreshed;
use SineMacula\Laravel\Sso\Events\JwksRefreshFailed;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokenValidator;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * The whole sequence and context of what an OIDC completion reports (SSO-10.1,
 * SSO-10.2, SSO-10.4, SSO-7.3), through the public path against the fake
 * provider: verified; verified after a refetch; a refetch that failed; each
 * refusal, reporting exactly one `FlowFailed`; and a refusal under the lock,
 * with `ResultVerified` before it. The request's reference is the only flow
 * identifier any of them carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionEvents::class)]
#[CoversClass(IdTokenValidator::class)]
final class OidcCompletionEventSequenceTest extends TestCase
{
    use CapturesLogs, RecordsEventSequences, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var string The tenant of the connection. */
    private const string TENANT = 'tenant-7';

    /** @var string The IP address every request comes from. */
    private const string IP = '203.0.113.7';

    /** @var string The user agent every request comes from. */
    private const string USER_AGENT = 'ExampleBrowser/1.0';

    /** @var string What every event's context says it occurred at. */
    private const string OCCURRED_AT = '2026-11-01T09:30:00.000000Z';

    /** @var string The session a `reauthenticate` is started on. */
    private const string SESSION = 'session-1';

    /** @var string The identity's class a `reauthenticate` is started for. */
    private const string IDENTITY_TYPE = 'App\Models\User';

    /** @var string The identity's id a `reauthenticate` is started for. */
    private const string IDENTITY_ID = '42';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's key, made once. */
    private static ?FakeSigningKey $key = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's next key, made once. */
    private static ?FakeSigningKey $next = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the provider answers on. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The public reference of the request started last. */
    private string $reference = '';

    /**
     * Bind a fixed clock, the fake fetcher and a request from a client, switch
     * OIDC on, register the application and the endpoints, create the tables
     * and serve the provider.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $clock          = new FixedClock('2026-11-01T09:30:00Z');
        $this->fetcher  = new FakeFetcher;
        $this->provider = (new FakeOpenIdProvider(FakeOpenIdProvider::ISSUER, self::key(), $clock))->serve($this->fetcher);

        $this->app?->instance(Clock::class, $clock);
        $this->app?->instance(Fetcher::class, $this->fetcher);
        $this->app?->instance('request', Request::create('https://sp.example.test/auth/sso/connections/x/callback', 'GET', server: [
            'REMOTE_ADDR'     => self::IP,
            'HTTP_USER_AGENT' => self::USER_AGENT,
        ]));

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->createDomainsTable();
        self::migration(self::SINGLE_USE_MIGRATION)->up(); // @phpstan-ignore method.notFound
        self::migration(self::RATE_LIMITS_MIGRATION)->up(); // @phpstan-ignore method.notFound

        $this->captureLogs();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::migration(self::RATE_LIMITS_MIGRATION)->down(); // @phpstan-ignore method.notFound
        self::migration(self::SINGLE_USE_MIGRATION)->down(); // @phpstan-ignore method.notFound
        $this->dropDomainsTable();
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A verified sign-in reports `ResultVerified` then `HandoffIssued`, each
     * with the whole context of the flow.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAVerifiedSignIn(): void
    {
        $connection = $this->connection();
        $grant      = $this->granted($connection);

        self::assertTrue($this->receiveCallback($connection, $grant)->isCompleted());

        $this->assertEventSequence([ResultVerified::class, HandoffIssued::class]);
        $this->assertNoFailure();

        foreach ($this->recordedEvents() as $event) {
            self::assertSame($this->flowContext($connection), $event->context()->toArray());
        }
    }

    /**
     * A verified `reauthenticate` carries the identity and the session it was
     * started for.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAVerifiedReauthentication(): void
    {
        $this->app?->instance(ReauthenticationSessions::class, new class implements ReauthenticationSessions {
            /**
             * Answer that the identity is signed in on the session.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            #[\Override]
            public function standing(IdentityReference $identity, string $sessionId, SsoConnection $connection): SessionStanding
            {
                unset($identity, $sessionId, $connection);

                return SessionStanding::SIGNED_IN;
            }
        });

        $connection = $this->connection();
        $url        = $this->startUrl($connection, Purpose::REAUTHENTICATE, new IdentityReference(self::IDENTITY_TYPE, self::IDENTITY_ID), self::SESSION);
        $grant      = $this->provider->authorize($url);

        $this->startRecordingEvents();

        self::assertTrue($this->receiveCallback($connection, $grant)->isCompleted());

        $this->assertEventSequence([ResultVerified::class, HandoffIssued::class]);

        $expected = [
            ...$this->flowContext($connection),
            'purpose'              => Purpose::REAUTHENTICATE->value,
            'identity_morph_class' => self::IDENTITY_TYPE,
            'identity_id'          => self::IDENTITY_ID,
            'session_id'           => self::SESSION,
        ];

        foreach ($this->recordedEvents() as $event) {
            self::assertSame($expected, $event->context()->toArray());
        }
    }

    /**
     * A key added at the provider: `JwksRefreshed`, naming the connection alone
     * since a refetch is the connection's, then the flow's two events.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAVerifiedSignInWithARefetch(): void
    {
        $connection = $this->connection();

        $this->provider->publish(self::next())->signWith(self::next());

        $grant = $this->granted($connection);

        self::assertTrue($this->receiveCallback($connection, $grant)->isCompleted());

        $this->assertEventSequence([JwksRefreshed::class, ResultVerified::class, HandoffIssued::class]);

        [$refreshed, $verified, $issued] = $this->recordedEvents();

        self::assertInstanceOf(JwksRefreshed::class, $refreshed);
        self::assertSame([1, 0, false], [$refreshed->keysAdded, $refreshed->keysRemoved, $refreshed->trustChanged]);
        self::assertSame((int) $connection->fresh()?->jwks_version, $refreshed->jwksVersion);
        self::assertSame($this->connectionContext($connection), $refreshed->context()->toArray());
        self::assertSame($this->flowContext($connection), $verified->context()->toArray());
        self::assertSame($this->flowContext($connection), $issued->context()->toArray());
    }

    /**
     * A key removed at the provider: the refetch voids what else is in flight
     * and spares its own flow, which finishes, with `ResultVerified` before its
     * `HandoffIssued`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARefetchThatRemovesAKeyFinishesItsOwnFlow(): void
    {
        $connection = $this->connection();

        $this->provider->unpublish('rsa-1')->publish(self::next())->signWith(self::next());

        $grant = $this->granted($connection);

        self::assertTrue($this->receiveCallback($connection, $grant)->isCompleted());

        $this->assertEventSequence([JwksRefreshed::class, ResultVerified::class, HandoffIssued::class]);

        [$refreshed, $verified] = $this->recordedEvents();

        self::assertInstanceOf(JwksRefreshed::class, $refreshed);
        self::assertSame([1, 1, true], [$refreshed->keysAdded, $refreshed->keysRemoved, $refreshed->trustChanged]);
        self::assertSame($this->flowContext($connection), $verified->context()->toArray());
        $this->assertNoFailure();
    }

    /**
     * A key removed at the provider and a further trust change before the
     * locks: the token verifies and the completion is refused under the lock,
     * with `ResultVerified` before its one `FlowFailed`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAFurtherTrustChangeAfterTheRefetchRefusesUnderTheLock(): void
    {
        $connection = $this->connection(['fetch_userinfo' => true, 'userinfo_endpoint' => $this->provider->endpoint('userinfo')]);

        $this->provider->unpublish('rsa-1')->publish(self::next())->signWith(self::next());
        $this->provider->respond('userinfo', static function (FetchRequest $request) use ($connection): FetchResult {
            unset($request);

            Connection::query()->whereKey($connection->id)->increment('trust_version');

            return FakeTokenEndpoint::json(200, ['sub' => FakeOpenIdProvider::SUBJECT]);
        });

        $grant = $this->granted($connection);

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->receiveCallback($connection, $grant)->reason);

        $this->assertEventSequence([JwksRefreshed::class, ResultVerified::class, FlowFailed::class]);

        [$refreshed, $verified, $failed] = $this->recordedEvents();

        self::assertInstanceOf(JwksRefreshed::class, $refreshed);
        self::assertSame($this->flowContext($connection), $verified->context()->toArray());
        self::assertSame($this->flowContext($connection), $failed->context()->toArray());
        self::assertSame($failed, $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::CONNECTION_UNAVAILABLE));
    }

    /**
     * Rows of `[response, reason]`: what a refetch's JWKS request is answered
     * with, and why it failed.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchResult, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideFailedRefetches(): iterable
    {
        $jwk = (string) json_encode(self::next()->jwk());

        yield from [
            'a timeout'           => [FetchResult::failed(), FailureReason::FETCH_FAILED],
            'an address refused'  => [FetchResult::refused(), FailureReason::FETCH_REFUSED],
            'a server error'      => [FetchResult::fetched(500, [], 'down'), FailureReason::FETCH_FAILED],
            'a body not JSON'     => [FetchResult::fetched(200, [], 'not json'), FailureReason::JWKS_INVALID],
            'a JWKS with no keys' => [FetchResult::fetched(200, [], '{"keys":[]}'), FailureReason::JWKS_INVALID],
            'a repeated member'   => [FetchResult::fetched(200, [], '{"keys":[],"keys":[' . $jwk . ']}'), FailureReason::JWKS_INVALID],
            'an escaped member'   => [FetchResult::fetched(200, [], '{"keys":[{"' . chr(92) . 'u006bty":"oct",' . substr($jwk, 1) . ']}'), FailureReason::JWKS_INVALID],
            'a key twice'         => [FetchResult::fetched(200, [], '{"keys":[' . $jwk . ',' . $jwk . ']}'), FailureReason::JWKS_INVALID],
            'keys an object'      => [FetchResult::fetched(200, [], '{"keys":{"0":' . $jwk . '}}'), FailureReason::JWKS_INVALID],
        ];
    }

    /**
     * A refetch that failed reports `JwksRefreshFailed`, naming when the next
     * may start, then the one `FlowFailed`, `signature_invalid`.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $response
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideFailedRefetches')]
    public function testARefetchThatFailed(FetchResult $response, FailureReason $reason): void
    {
        $connection = $this->connection();

        $this->provider->respond('jwks', $response)->signWith(self::next());

        $grant = $this->granted($connection);

        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->receiveCallback($connection, $grant)->reason);

        $this->assertEventSequence([JwksRefreshFailed::class, FlowFailed::class]);

        [$refetch, $failed] = $this->recordedEvents();

        self::assertInstanceOf(JwksRefreshFailed::class, $refetch);
        self::assertSame($reason, $refetch->reason);
        self::assertSame('2026-11-01T09:35:00+00:00', $refetch->nextRefetchAt?->toIso8601String());
        self::assertSame($this->connectionContext($connection), $refetch->context()->toArray());
        self::assertSame($this->flowContext($connection), $failed->context()->toArray());
        self::assertSame($failed, $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::SIGNATURE_INVALID));
    }

    /**
     * Rows of `[tailor, reason]`: a token a check refuses.
     *
     * @return iterable<string, array{
     *     0: \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): (\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken|string),
     *     1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason
     * }>
     */
    public static function provideRefusedTokens(): iterable
    {
        yield from [
            'not a token'   => [static fn (FakeIdToken $t): string => 'not-a-token', FailureReason::ID_TOKEN_INVALID],
            'a forged key'  => [static fn (FakeIdToken $t): FakeIdToken => $t->withHeader('alg', 'HS256')->hmac('x'), FailureReason::SIGNATURE_INVALID],
            'a wrong type'  => [static fn (FakeIdToken $t): FakeIdToken => $t->with('sub', 1), FailureReason::ID_TOKEN_INVALID],
            'iss wrong'     => [static fn (FakeIdToken $t): FakeIdToken => $t->with('iss', 'https://other.example.test'), FailureReason::ISSUER_MISMATCH],
            'aud wrong'     => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', 'another-client'), FailureReason::AUDIENCE_MISMATCH],
            'exp passed'    => [static fn (FakeIdToken $t): FakeIdToken => $t->with('exp', 1), FailureReason::ASSERTION_EXPIRED],
            'nonce wrong'   => [static fn (FakeIdToken $t): FakeIdToken => $t->with('nonce', 'another-nonce'), FailureReason::NONCE_MISMATCH],
            'at_hash wrong' => [static fn (FakeIdToken $t): FakeIdToken => $t->with('at_hash', 'wrong'), FailureReason::AT_HASH_MISMATCH],
        ];
    }

    /**
     * Each refused token reports one `FlowFailed`, with the flow's whole
     * context, and nothing else: a result was never verified.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): (\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken|string)  $tailor
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideRefusedTokens')]
    public function testARefusedTokenReportsOneFailure(\Closure $tailor, FailureReason $reason): void
    {
        $connection = $this->connection();
        $grant      = $this->granted($connection, $tailor);

        self::assertSame($reason, $this->receiveCallback($connection, $grant)->reason);

        $this->assertOneFailure($connection, $reason);
    }

    /**
     * An authentication too old for `max_age` reports one `FlowFailed`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnAuthenticationTooOldReportsOneFailure(): void
    {
        $connection = $this->connection(['max_age' => 300]);
        $grant      = $this->granted($connection, static fn (FakeIdToken $t): FakeIdToken => $t->with('auth_time', 1));

        self::assertSame(FailureReason::AUTHENTICATION_EXPIRED, $this->receiveCallback($connection, $grant)->reason);

        $this->assertOneFailure($connection, FailureReason::AUTHENTICATION_EXPIRED);
    }

    /**
     * Rows of `[response, reason]`: a token endpoint's answer that is refused.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchResult, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideTokenAnswers(): iterable
    {
        yield from [
            'an error'       => [FakeTokenEndpoint::json(400, ['error' => 'invalid_grant']), FailureReason::PROVIDER_ERROR],
            'a server error' => [FakeTokenEndpoint::json(500, []), FailureReason::FETCH_FAILED],
            'a timeout'      => [FetchResult::failed(), FailureReason::FETCH_FAILED],
            'no ID token'    => [FakeTokenEndpoint::json(200, ['access_token' => 'a', 'token_type' => 'Bearer']), FailureReason::ID_TOKEN_INVALID],
            'not an object'  => [FetchResult::fetched(200, [], '[]'), FailureReason::TOKEN_RESPONSE_INVALID],
        ];
    }

    /**
     * A refused token response reports one `FlowFailed`.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $answer
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideTokenAnswers')]
    public function testARefusedTokenResponseReportsOneFailure(FetchResult $answer, FailureReason $reason): void
    {
        $connection = $this->connection();
        $grant      = $this->granted($connection);

        $this->provider->respond('token', $answer);

        self::assertSame($reason, $this->receiveCallback($connection, $grant)->reason);

        $this->assertOneFailure($connection, $reason);
    }

    /**
     * Rows of `[query, reason]`: a callback refused before any token request.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization): string, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideCallbacks(): iterable
    {
        yield from [
            'a provider error' => [static fn (FakeAuthorization $grant): string => $grant->errorQuery('access_denied', 'not shown'), FailureReason::PROVIDER_ERROR],
            'another issuer'   => [static fn (FakeAuthorization $grant): string => $grant->query(['iss' => 'https://other.example.test']), FailureReason::ISSUER_MISMATCH],
            'no code'          => [static fn (FakeAuthorization $grant): string => $grant->query(['code' => null]), FailureReason::RESPONSE_INVALID],
        ];
    }

    /**
     * A refused callback reports one `FlowFailed`.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization): string  $query
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideCallbacks')]
    public function testARefusedCallbackReportsOneFailure(\Closure $query, FailureReason $reason): void
    {
        $connection = $this->connection();
        $grant      = $this->granted($connection);

        $result = app(CompletionService::class)->callback($connection->id, new CompletionRequest('GET', $query($grant), []));

        self::assertSame($reason, $result->reason);

        $this->assertOneFailure($connection, $reason);
    }

    /**
     * Rows of `[answer, reason]`: a UserInfo answer that is refused.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchResult, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideUserInfoAnswers(): iterable
    {
        yield from [
            'an error'    => [FakeTokenEndpoint::json(401, ['error' => 'invalid_token']), FailureReason::PROVIDER_ERROR],
            'a timeout'   => [FetchResult::failed(), FailureReason::FETCH_FAILED],
            'another sub' => [FakeTokenEndpoint::json(200, ['sub' => 'someone-else']), FailureReason::USERINFO_INVALID],
        ];
    }

    /**
     * A UserInfo answer refused fails the completion closed, with one
     * `FlowFailed`: the token verified, the result never did.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $answer
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideUserInfoAnswers')]
    public function testARefusedUserInfoReportsOneFailure(FetchResult $answer, FailureReason $reason): void
    {
        $connection = $this->connection(['fetch_userinfo' => true, 'userinfo_endpoint' => $this->provider->endpoint('userinfo')]);
        $grant      = $this->granted($connection);

        $this->provider->respond('userinfo', $answer);

        self::assertSame($reason, $this->receiveCallback($connection, $grant)->reason);

        $this->assertOneFailure($connection, $reason);
    }

    /**
     * Assert the flow reported one `FlowFailed` for the reason, with its whole
     * context, and nothing else.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    private function assertOneFailure(Connection $connection, FailureReason $reason): void
    {
        $this->assertEventSequence([FlowFailed::class]);

        self::assertSame($this->flowContext($connection), $this->assertExactlyOneFailure(Flow::CALLBACK, $reason)->context()->toArray());
    }

    /**
     * The whole context of a completion of a `sign_in` through the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return array<string, ?string>
     */
    private function flowContext(Connection $connection): array
    {
        return [...$this->connectionContext($connection), 'application' => 'web', 'purpose' => Purpose::SIGN_IN->value, 'request_reference' => $this->reference];
    }

    /**
     * The whole context of what concerns the connection alone.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return array<string, ?string>
     */
    private function connectionContext(Connection $connection): array
    {
        return [
            'occurred_at'                 => self::OCCURRED_AT,
            'ip'                          => self::IP,
            'user_agent'                  => self::USER_AGENT,
            'connection_id'               => $connection->id,
            'tenant_id'                   => self::TENANT,
            'protocol'                    => 'oidc',
            'application'                 => null,
            'purpose'                     => null,
            'request_reference'           => null,
            'identity_morph_class'        => null,
            'identity_id'                 => null,
            'acting_identity_morph_class' => null,
            'acting_identity_id'          => null,
            'principal_morph_class'       => null,
            'principal_id'                => null,
            'active_tenant_id'            => null,
            'session_id'                  => null,
            'method'                      => null,
        ];
    }

    /**
     * Complete at the connection's callback with the grant's query.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization  $grant
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function receiveCallback(Connection $connection, FakeAuthorization $grant): CompletionResult
    {
        return app(CompletionService::class)->callback($connection->id, new CompletionRequest('GET', $grant->query(), []));
    }

    /**
     * Start a sign-in through the connection, have the provider grant it, and
     * record events from there.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): (\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken|string)  $tailor
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization
     *
     * @throws \Random\RandomException
     */
    private function granted(Connection $connection, ?\Closure $tailor = null): FakeAuthorization
    {
        $grant = $this->provider->authorize($this->startUrl($connection), $tailor);

        $this->startRecordingEvents();

        return $grant;
    }

    /**
     * Start a flow through the connection; the URL it sends the browser to.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $session
     * @return string
     */
    private function startUrl(Connection $connection, Purpose $purpose = Purpose::SIGN_IN, ?IdentityReference $identity = null, ?string $session = null): string
    {
        $started = app(AuthorizationRequestService::class)->start('web', $purpose, $connection->id, null, $identity, $session);

        self::assertTrue($started->isStarted());

        $this->reference = (string) $started->reference?->value;

        return (string) $started->navigation?->url();
    }

    /**
     * An enabled connection of the provider, storing its key.
     *
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connection(array $settings = []): Connection
    {
        $jwks = (string) json_encode(['keys' => [self::key()->jwk()]]);

        return $this->makeConnection([
            'tenant_id' => self::TENANT,
            'enabled'   => true,
            'jwks'      => ProviderKeySet::read($jwks, AlgorithmAllowList::of(['RS256']), 65536, 50)?->toStored(),
            'secrets'   => app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret(FakeOpenIdProvider::CLIENT_SECRET)]),
            'settings'  => [
                'issuer'                 => $this->provider->issuer,
                'authorization_endpoint' => $this->provider->endpoint('authorization'),
                'token_endpoint'         => $this->provider->endpoint('token'),
                'jwks_uri'               => $this->provider->endpoint('jwks'),
                'client_id'              => FakeOpenIdProvider::CLIENT_ID,
                ...$settings,
            ],
        ]);
    }

    /**
     * The provider's key, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(): FakeSigningKey
    {
        return self::$key ??= FakeSigningKey::rsa('rsa-1');
    }

    /**
     * The provider's next key, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function next(): FakeSigningKey
    {
        return self::$next ??= FakeSigningKey::rsa('rsa-2');
    }

    /**
     * The shipped migration of the file.
     *
     * @param  string  $file
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function migration(string $file): Migration
    {
        return require dirname(__DIR__, 3) . $file;
    }
}
