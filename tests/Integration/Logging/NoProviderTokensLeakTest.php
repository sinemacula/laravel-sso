<?php

declare(strict_types = 1);

namespace Tests\Integration\Logging;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Logging\SanitizingLogger;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokenValidator;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\DumpsValues;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Provider tokens are never kept (SSO-7.6, SSO-11.9, SSO-5.7), run end to end
 * through the public path, for verified and refused flows alike: every event
 * dispatched (serialised, as JSON and dumped), every log record and its
 * context, the result, every stored row of every table the flow writes, the
 * handoff's decrypted result, and every dump of the values involved. None holds
 * the access token, the refresh token, the ID token or a segment of it, the
 * code, the state, the nonce, the PKCE verifier, the client secret, the client
 * assertion, a UserInfo body or an `error_description`, and the request's
 * reference is the only flow identifier any event or log carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdTokenValidator::class)]
#[CoversClass(SanitizingLogger::class)]
final class NoProviderTokensLeakTest extends TestCase
{
    use CapturesLogs, DumpsValues, RecordsEventSequences, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var string What a provider's `error_description` holds. */
    private const string DESCRIPTION = 'description-never-reported';

    /** @var string A claim a UserInfo body holds that nothing keeps, since nothing maps it. */
    private const string USERINFO_NOTE = 'userinfo-note-never-kept';

    /** @var list<string> What a log record's context may name. */
    private const array LOG_CONTEXT = ['connection_id', 'request_reference', 'error', 'reason', 'fetch_status'];

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's key, made once. */
    private static ?FakeSigningKey $key = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's next key, made once. */
    private static ?FakeSigningKey $next = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The connection's client assertion key, made once. */
    private static ?FakeSigningKey $clientKey = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the provider answers on. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The public reference of the request started last. */
    private string $reference = '';

    /** @var string The verifier generated for the client of the request started last. */
    private string $clientVerifier = '';

    /**
     * Bind a fixed clock, the fake fetcher and a request from a client, switch
     * OIDC on, register the application and the endpoints, create the tables,
     * serve the provider, capture logs and record events. The default handoff
     * store is left in place, so a code is stored as it would be.
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
        $this->app?->instance('request', Request::create('https://sp.example.test/auth/sso/connections/x/callback', 'GET', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->createDomainsTable();
        self::migration(self::SINGLE_USE_MIGRATION)->up(); // @phpstan-ignore method.notFound
        self::migration(self::RATE_LIMITS_MIGRATION)->up(); // @phpstan-ignore method.notFound

        $this->captureLogs();
        $this->startRecordingEvents();
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
     * A verified flow keeps nothing, and its handoff is really stored.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAVerifiedFlowKeepsNothing(): void
    {
        $connection = $this->connection();
        $grant      = $this->granted($connection);
        $result     = $this->receiveCallback($connection, $grant);

        self::assertTrue($result->isCompleted());
        self::assertSame(1, HandoffCode::query()->count());

        $this->assertNothingKept($result, $this->needles($grant));
    }

    /**
     * A flow verified with UserInfo keeps nothing of its body, whatever claim
     * it carries, nor the access token it was fetched with.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAVerifiedFlowWithUserInfoKeepsNothing(): void
    {
        $connection = $this->connection(['fetch_userinfo' => true, 'userinfo_endpoint' => $this->provider->endpoint('userinfo')]);
        $grant      = $this->granted($connection);
        $body       = (string) json_encode(['sub' => FakeOpenIdProvider::SUBJECT, 'note' => self::USERINFO_NOTE, 'access_token' => $grant->accessToken], JSON_UNESCAPED_SLASHES);

        $this->provider->respond('userinfo', FetchResult::fetched(200, ['Content-Type' => 'application/json'], $body));

        $result = $this->receiveCallback($connection, $grant);

        self::assertTrue($result->isCompleted());

        $this->assertNothingKept($result, [...$this->needles($grant), $body, self::USERINFO_NOTE]);
    }

    /**
     * A flow verified by `private_key_jwt` keeps nothing of its client
     * assertion.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAVerifiedFlowByClientAssertionKeepsNothing(): void
    {
        $this->provider->register(FakeOpenIdProvider::CLIENT_ID, 'private_key_jwt', null, self::clientSigningKey()->publicKeyPem);

        $connection = $this->connection(['client_authentication' => 'private_key_jwt'], false);

        $this->clientKey($connection);

        $grant  = $this->granted($connection);
        $result = $this->receiveCallback($connection, $grant);

        self::assertTrue($result->isCompleted());

        $requests = array_values(array_filter($this->fetcher->requests(), static fn (FetchRequest $request): bool => $request->purpose === FetchPurpose::TOKEN));

        self::assertCount(1, $requests);
        self::assertSame(CredentialKind::PRIVATE_KEY_JWT, $requests[0]->credentials?->kind);

        $assertion = $requests[0]->credentials->secret();

        $this->assertNothingKept($result, [...$this->needles($grant), $assertion, ...explode('.', $assertion)]);
    }

    /**
     * A flow verified after a refetch keeps nothing, and what the refetch logs
     * names no flow.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAVerifiedFlowAfterARefetchKeepsNothing(): void
    {
        $connection = $this->connection();

        $this->provider->publish(self::next())->signWith(self::next());

        $grant  = $this->granted($connection);
        $result = $this->receiveCallback($connection, $grant);

        self::assertTrue($result->isCompleted());
        $this->assertLoggedContains('sso.oidc.jwks_refetch_refreshed');

        $this->assertNothingKept($result, $this->needles($grant));
    }

    /**
     * Rows of `[tailor, reason]`: a token refused at each check.
     *
     * @return iterable<string, array{
     *     0: \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): (\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken|string),
     *     1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason
     * }>
     */
    public static function provideRefusedTokens(): iterable
    {
        yield from [
            'unsigned'      => [static fn (FakeIdToken $t): FakeIdToken => $t->withHeader('alg', 'none')->unsigned(), FailureReason::ID_TOKEN_INVALID],
            'an HMAC'       => [static fn (FakeIdToken $t): FakeIdToken => $t->withHeader('alg', 'HS256')->hmac(self::key()->publicKeyPem), FailureReason::SIGNATURE_INVALID],
            'unknown kid'   => [static fn (FakeIdToken $t): FakeIdToken => $t->withHeader('kid', 'unknown'), FailureReason::SIGNATURE_INVALID],
            'a wrong type'  => [static fn (FakeIdToken $t): FakeIdToken => $t->with('sub', 1), FailureReason::ID_TOKEN_INVALID],
            'iss wrong'     => [static fn (FakeIdToken $t): FakeIdToken => $t->with('iss', 'https://other.example.test'), FailureReason::ISSUER_MISMATCH],
            'aud wrong'     => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', 'another-client'), FailureReason::AUDIENCE_MISMATCH],
            'exp passed'    => [static fn (FakeIdToken $t): FakeIdToken => $t->with('exp', 1), FailureReason::ASSERTION_EXPIRED],
            'nonce wrong'   => [static fn (FakeIdToken $t): FakeIdToken => $t->with('nonce', 'another-nonce-value'), FailureReason::NONCE_MISMATCH],
            'at_hash wrong' => [static fn (FakeIdToken $t): FakeIdToken => $t->with('at_hash', 'wrong-at-hash-value'), FailureReason::AT_HASH_MISMATCH],
        ];
    }

    /**
     * A flow refused at each check of the token keeps nothing, the tailored
     * values included.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): (\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken|string)  $tailor
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideRefusedTokens')]
    public function testARefusedTokenKeepsNothing(\Closure $tailor, FailureReason $reason): void
    {
        $connection = $this->connection();
        $grant      = $this->granted($connection, $tailor);
        $result     = $this->receiveCallback($connection, $grant);

        self::assertSame($reason, $result->reason);
        self::assertSame(0, HandoffCode::query()->count());

        $this->assertNothingKept($result, [...$this->needles($grant), 'another-nonce-value', 'wrong-at-hash-value']);
    }

    /**
     * A provider's error on the callback is logged by its code, with its
     * description nowhere.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACallbackErrorKeepsItsDescriptionNowhere(): void
    {
        $connection = $this->connection();
        $grant      = $this->granted($connection);
        $result     = app(CompletionService::class)->callback($connection->id, new CompletionRequest('GET', $grant->errorQuery('access_denied', self::DESCRIPTION), []));

        self::assertSame(FailureReason::PROVIDER_ERROR, $result->reason);
        $this->assertLoggedContains('sso.oidc.callback_error', 'access_denied', $this->reference);

        $this->assertNothingKept($result, $this->needles($grant));
    }

    /**
     * Rows of `[error, logged]`: a token error's `error`, and what is logged of
     * it: its code, or nothing of prose.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideTokenErrors(): iterable
    {
        yield from [
            'a code' => ['invalid_grant', 'invalid_grant'],
            'prose'  => ['the prose ' . self::DESCRIPTION, '[unrecognized]'],
        ];
    }

    /**
     * A token endpoint's error is logged by its code alone, whatever it says.
     *
     * @param  string  $error
     * @param  string  $logged
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideTokenErrors')]
    public function testATokenErrorKeepsItsDescriptionNowhere(string $error, string $logged): void
    {
        $connection = $this->connection();
        $grant      = $this->granted($connection);

        $body = ['error' => $error, 'error_description' => self::DESCRIPTION, 'error_uri' => 'https://op.example.test/' . self::DESCRIPTION];

        $this->provider->respond('token', FakeTokenEndpoint::json(400, $body));

        $result = $this->receiveCallback($connection, $grant);

        self::assertSame(FailureReason::PROVIDER_ERROR, $result->reason);
        $this->assertLoggedContains('sso.oidc.token_error', $logged, $this->reference);

        $this->assertNothingKept($result, $this->needles($grant));
    }

    /**
     * Rows of `[status, headers, reason]`: a UserInfo error whose body and
     * headers carry what must never be kept.
     *
     * @return iterable<string, array{0: int, 1: array<string, string>, 2: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideUserInfoErrors(): iterable
    {
        yield from [
            'a 401 with a description' => [
                401,
                ['WWW-Authenticate' => 'Bearer error="invalid_token", error_description="' . self::DESCRIPTION . '"'],
                FailureReason::PROVIDER_ERROR,
            ],
            'a 403 with a description' => [
                403,
                ['WWW-Authenticate' => 'Bearer error="insufficient_scope", error_description="' . self::DESCRIPTION . '"'],
                FailureReason::PROVIDER_ERROR,
            ],
            'a 500'           => [500, ['Content-Type' => 'application/json'], FailureReason::FETCH_FAILED],
            'another subject' => [200, ['Content-Type' => 'application/json'], FailureReason::USERINFO_INVALID],
        ];
    }

    /**
     * A UserInfo error keeps its body and its description nowhere.
     *
     * @param  int  $status
     * @param  array<string, string>  $headers
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideUserInfoErrors')]
    public function testAUserInfoErrorKeepsItsBodyNowhere(int $status, array $headers, FailureReason $reason): void
    {
        $connection = $this->connection(['fetch_userinfo' => true, 'userinfo_endpoint' => $this->provider->endpoint('userinfo')]);
        $grant      = $this->granted($connection);
        $answer     = ['sub' => 'someone-else', 'note' => self::USERINFO_NOTE, 'error_description' => self::DESCRIPTION, 'access_token' => $grant->accessToken];
        $body       = (string) json_encode($answer, JSON_UNESCAPED_SLASHES);

        $this->provider->respond('userinfo', FetchResult::fetched($status, $headers, $body));

        $result = $this->receiveCallback($connection, $grant);

        self::assertSame($reason, $result->reason);

        $this->assertNothingKept($result, [...$this->needles($grant), $body, self::USERINFO_NOTE, 'someone-else']);
    }

    /**
     * A JWKS refused whole keeps nothing of its body, and its private key least
     * of all, the keys stored staying as they were.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARefusedJwksKeepsNothing(): void
    {
        $connection = $this->connection();
        $private    = self::next()->privateJwk();
        $secret     = is_string($private['d'] ?? null) ? $private['d'] : '';

        self::assertNotSame('', $secret);

        $this->provider->respond('jwks', FakeTokenEndpoint::json(200, ['keys' => [$private]]));
        $this->provider->signWith(self::next());

        $grant  = $this->granted($connection);
        $result = $this->receiveCallback($connection, $grant);

        self::assertSame(FailureReason::SIGNATURE_INVALID, $result->reason);
        $this->assertLoggedContains('sso.oidc.jwks_refetch_failed');

        $this->assertNothingKept($result, [...$this->needles($grant), $secret]);
    }

    /**
     * A flow refused under the lock, its token verified first, keeps nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARefusalUnderTheLockKeepsNothing(): void
    {
        $connection = $this->connection();

        $this->provider->unpublish('rsa-1')->publish(self::next())->signWith(self::next());

        $grant  = $this->granted($connection);
        $result = $this->receiveCallback($connection, $grant);

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $result->reason);

        $this->assertNothingKept($result, $this->needles($grant));
    }

    /**
     * Assert that nothing the flow dispatched, logged, answered, stored or was
     * given holds any of the needles, and that the request's reference is the
     * only flow identifier any event or log carries.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @param  list<string>  $needles
     * @return void
     */
    private function assertNothingKept(CompletionResult $result, array $needles): void
    {
        $needles = array_values(array_filter($needles, static fn (string $needle): bool => $needle !== ''));

        self::assertNotSame([], $this->recordedEvents());

        $this->assertNothingLoggedContains(...$needles);

        $json  = (string) json_encode($result, JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
        $texts = [...$this->eventTexts(), ...self::dumps($result), 'result JSON' => $json, ...$this->storedTexts(), ...$this->requestTexts()];

        foreach ($texts as $where => $text) {
            foreach ($needles as $needle) {
                self::assertStringNotContainsString($needle, $text, $where);
            }
        }

        $this->assertOnlyTheReferenceIdentifiesTheFlow();
    }

    /**
     * Assert that each event names the flow by the request's reference or not
     * at all, and that a log names nothing but what it may.
     *
     * @return void
     */
    private function assertOnlyTheReferenceIdentifiesTheFlow(): void
    {
        foreach ($this->recordedEvents() as $event) {
            self::assertContains($event->context()->requestReference, [null, $this->reference]);
        }

        foreach ($this->capturedLogRecords() as $record) {

            self::assertSame([], array_values(array_diff(array_map(strval(...), array_keys($record['context'])), self::LOG_CONTEXT)), $record['message']);

            if (!array_key_exists('request_reference', $record['context'])) {
                continue;
            }

            self::assertSame($this->reference, $record['context']['request_reference']);
        }
    }

    /**
     * Each event dispatched, every way a listener or a queue could read it.
     *
     * @return array<string, string>
     */
    private function eventTexts(): array
    {
        $texts = [];

        foreach ($this->recordedEvents() as $index => $event) {

            $name = "event {$index} " . $event::class;

            $texts["{$name} serialised"] = serialize($event);
            $texts["{$name} JSON"]       = (string) json_encode($event, JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
            $texts["{$name} context"]    = (string) json_encode($event->context()->toArray(), JSON_UNESCAPED_SLASHES);

            foreach (self::dumps($event) as $how => $dump) {
                $texts["{$name} {$how}"] = $dump;
            }
        }

        return $texts;
    }

    /**
     * Every row of every table the package keeps, each column as stored, with
     * the verified result a handoff carries decrypted.
     *
     * @return array<string, string>
     */
    private function storedTexts(): array
    {
        $texts = [];

        foreach (['connections', 'keys', 'domains', 'links', 'authorization_requests', 'handoff_codes', 'single_use', 'rate_limits'] as $section) {

            $table = config("sso.{$section}.table");

            self::assertIsString($table);

            $rows = DB::connection(StorageConnection::name())->table($table)->get()->map(static fn (object $row): array => (array) $row)->all();

            $texts["stored {$table}"] = (string) json_encode($rows, JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
        }

        foreach (HandoffCode::query()->get() as $code) {
            $texts["handoff result {$code->id}"] = app(SecretEncrypter::class)->decrypt($code->result);
        }

        return $texts;
    }

    /**
     * Every dump of the values the flow handled: each request it made through
     * the fetcher and what holds the provider's tokens.
     *
     * @return array<string, string>
     */
    private function requestTexts(): array
    {
        $texts = [];

        foreach ($this->fetcher->requests() as $index => $request) {
            foreach (self::dumps($request) as $how => $dump) {
                $texts["request {$index} {$how}"] = $dump;
            }
        }

        $token  = (string) $this->provider->idToken(['nonce' => 'a-nonce-never-shown']);
        $values = ['tokens' => new TokenResponse($token, 'an-access-token'), 'compact token' => CompactToken::parse($token, 16384)];

        foreach ($values as $name => $value) {

            self::assertStringNotContainsString($token, implode("\n", self::dumps($value)));

            foreach (self::dumps($value) as $how => $dump) {
                self::assertStringNotContainsString('a-nonce-never-shown', $dump, "{$name} {$how}");
                $texts["{$name} {$how}"] = $dump;
            }
        }

        return $texts;
    }

    /**
     * Everything a flow must keep nowhere, for the authorisation granted.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization  $grant
     * @return list<string>
     */
    private function needles(FakeAuthorization $grant): array
    {
        $token    = (string) $grant->idToken;
        $request  = AuthorizationRequest::query()->where('reference', $this->reference)->firstOrFail();
        $verifier = app(SecretEncrypter::class)->decrypt((string) $request->code_verifier);

        return [
            $grant->code,
            $grant->accessToken,
            'fake-refresh-' . $grant->code,
            $token,
            ...explode('.', $token),
            (string) $grant->parameter('state'),
            (string) $grant->parameter('nonce'),
            $verifier,
            $this->clientVerifier,
            FakeOpenIdProvider::CLIENT_SECRET,
            self::DESCRIPTION,
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
     * Start a sign-in through the connection, and have the provider grant it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): (\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken|string)  $tailor
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization
     *
     * @throws \Random\RandomException
     */
    private function granted(Connection $connection, ?\Closure $tailor = null): FakeAuthorization
    {
        $started = app(AuthorizationRequestService::class)->start('web', Purpose::SIGN_IN, $connection->id);

        self::assertTrue($started->isStarted());

        $this->reference      = (string) $started->reference?->value;
        $this->clientVerifier = (string) $started->verifier?->reveal();

        return $this->provider->authorize((string) $started->navigation?->url(), $tailor);
    }

    /**
     * An enabled connection of the provider storing its key, with the settings
     * given and a client secret unless told otherwise.
     *
     * @param  array<string, mixed>  $settings
     * @param  bool  $secret
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connection(array $settings = [], bool $secret = true): Connection
    {
        $jwks = (string) json_encode(['keys' => [self::key()->jwk()]]);

        return $this->makeConnection([
            'enabled'  => true,
            'jwks'     => ProviderKeySet::read($jwks, AlgorithmAllowList::of(['RS256']), 65536, 50)?->toStored(),
            'secrets'  => $secret ? app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret(FakeOpenIdProvider::CLIENT_SECRET)]) : null,
            'settings' => [
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
            'made_current_at' => app(Clock::class)->now(),
        ])->save();
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
     * The connection's client assertion key, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function clientSigningKey(): FakeSigningKey
    {
        return self::$clientKey ??= FakeSigningKey::ec('client-assertion-key');
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
