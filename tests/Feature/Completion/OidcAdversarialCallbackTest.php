<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\JwksRefreshed;
use SineMacula\Laravel\Sso\Events\JwksRefreshFailed;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokenValidator;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\HostileIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\HostileIdTokens;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Links\FixedLinker;
use Tests\TestCase;

/**
 * Feature tests for hostile ID tokens through the public callback path.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdTokenValidator::class)]
#[CoversClass(CompletionService::class)]
final class OidcAdversarialCallbackTest extends TestCase
{
    use CapturesLogs, RecordsEventSequences, UsesConnections;

    /** @var string The application's redirect URI. */
    private const string REDIRECT_URI = 'https://app.example.com/sso';

    /** @var int The clock skew the cases are built for and judged with. */
    private const int SKEW = 60;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\HostileIdTokens The cases' keys, made once. */
    private static ?HostileIdTokens $hostile = null;

    /** @var ?array<string, \SineMacula\Laravel\Sso\Testing\Oidc\HostileIdToken> Each case's JWKS, allow-list, stage and reason, made once. */
    private static ?array $cases = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's next key, made once. */
    private static ?FakeSigningKey $next = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package and the provider read. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the provider answers on. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider, signing with `k1`. */
    private FakeOpenIdProvider $provider;

    /** @var string The public reference of the request started last. */
    private string $reference = '';

    /**
     * Bind a fixed clock, the fake fetcher and a request; serve the provider.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock    = new FixedClock('2026-11-01T09:30:00Z');
        $this->fetcher  = new FakeFetcher;
        $this->provider = (new FakeOpenIdProvider(FakeOpenIdProvider::ISSUER, self::hostile()->rsa, $this->clock))->serve($this->fetcher);

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Fetcher::class, $this->fetcher);
        $this->app?->instance('request', Request::create('https://sp.example.test/auth/sso/connections/x/callback', 'GET', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.oidc', true);
        config()->set('sso.clock.skew_seconds', self::SKEW);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => self::REDIRECT_URI, 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->usePackageTables();

        $this->captureLogs();
    }

    /**
     * Rows of `[name]`: every hostile case.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideHostileCases(): iterable
    {
        foreach (array_keys(self::cases()) as $name) {
            yield $name => [$name];
        }
    }

    /**
     * Each hostile token is refused through the callback with its reason.
     *
     * @param  string  $name
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideHostileCases')]
    public function testEachHostileTokenIsRefusedThroughTheCallback(string $name): void
    {
        $case       = self::cases()[$name];
        $connection = $this->hostileConnection($case);
        $grant      = $this->granted($connection, static fn (FakeIdToken $honest): string => self::hostile()->cases($honest->claims(), self::SKEW)[$name]->token);
        $request    = $this->latestRequest();

        $this->startRecordingEvents();

        $result = $this->receiveCallback($connection, $grant);

        $this->assertRefused($result, $case->reason, $request);
        self::assertSame(in_array($case->stage, ['unknown', 'jwks_refused'], true) ? [FetchPurpose::TOKEN, FetchPurpose::JWKS] : [FetchPurpose::TOKEN], $this->fetchPurposes());

        $this->assertEventSequence(match ($case->stage) {
            'unknown'      => [JwksRefreshed::class, FlowFailed::class],
            'jwks_refused' => [JwksRefreshFailed::class, FlowFailed::class],
            default        => [FlowFailed::class],
        });

        $first = $this->recordedEvents()[0];

        if ($first instanceof JwksRefreshed) {
            self::assertFalse($first->trustChanged);
        }

        if (!$first instanceof JwksRefreshFailed) {
            return;
        }

        self::assertSame(FailureReason::JWKS_INVALID, $first->reason);
        self::assertNull($connection->fresh()?->jwks);
    }

    /**
     * A JWKS refused whole is reported `jwks_invalid`, keys unchanged.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARefusedJwksIsReportedInvalid(): void
    {
        $case       = self::cases()['a JWKS publishing a private key'];
        $connection = $this->hostileConnection($case);
        $case       = 'a JWKS publishing a private key';
        $grant      = $this->granted($connection, static fn (FakeIdToken $honest): string => self::hostile()->cases($honest->claims(), self::SKEW)[$case]->token);

        $this->startRecordingEvents();

        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->receiveCallback($connection, $grant)->reason);

        $failure = $this->recordedEvents()[0];

        self::assertInstanceOf(JwksRefreshFailed::class, $failure);
        self::assertSame(FailureReason::JWKS_INVALID, $failure->reason);
        self::assertNull($connection->fresh()?->jwks);
    }

    /**
     * Unknown `kid`s within the cooldown fetch nothing more.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testLaterUnknownKidsWithinTheCooldownFetchNothing(): void
    {
        $connection = $this->honestConnection();

        foreach (['unknown-1' => 1, 'unknown-2' => 1] as $kid => $fetches) {
            $this->assertUnknownKidIsRefused($connection, $kid, $fetches);
        }

        $this->clock->advance(299);
        $this->assertUnknownKidIsRefused($connection, 'unknown-3', 1);

        $this->clock->advance(1);
        $this->assertUnknownKidIsRefused($connection, 'unknown-4', 2);
    }

    /**
     * An unknown `kid` within the cooldown reports no refetch.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnUnknownKidInTheCooldownReportsNoRefetch(): void
    {
        $connection = $this->honestConnection();

        $this->assertUnknownKidIsRefused($connection, 'unknown-1', 1);

        $grant = $this->granted($connection, static fn (FakeIdToken $honest): FakeIdToken => $honest->withHeader('kid', 'unknown-2'));

        $this->startRecordingEvents();

        $this->assertRefused($this->receiveCallback($connection, $grant), FailureReason::SIGNATURE_INVALID, $this->latestRequest(), 2);
        $this->assertEventSequence([FlowFailed::class]);
    }

    /**
     * Rows of `[settings, tailor, reason]` for an ID token with wrong claims.
     *
     * @return iterable<string, array{
     *     0: array<string, mixed>,
     *     1: \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken,
     *     2: \SineMacula\Laravel\Sso\Events\Enums\FailureReason
     * }>
     */
    public static function provideWrongClaims(): iterable
    {
        yield from [
            'aud wrong'             => [[], static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', 'another-client'), FailureReason::AUDIENCE_MISMATCH],
            'aud with an untrusted' => [
                [],
                static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', [FakeOpenIdProvider::CLIENT_ID, 'untrusted'])->with('azp', FakeOpenIdProvider::CLIENT_ID),
                FailureReason::AUDIENCE_MISMATCH,
            ],
            'aud with a trusted, no azp' => [
                ['trusted_audiences' => ['trusted']],
                static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', [FakeOpenIdProvider::CLIENT_ID, 'trusted']),
                FailureReason::AUDIENCE_MISMATCH,
            ],
            'nonce wrong'             => [[], static fn (FakeIdToken $t): FakeIdToken => $t->with('nonce', 'another-nonce'), FailureReason::NONCE_MISMATCH],
            'nonce missing'           => [[], static fn (FakeIdToken $t): FakeIdToken => $t->without('nonce'), FailureReason::NONCE_MISMATCH],
            'iss wrong'               => [[], static fn (FakeIdToken $t): FakeIdToken => $t->with('iss', 'https://other.example.test'), FailureReason::ISSUER_MISMATCH],
            'azp wrong'               => [[], static fn (FakeIdToken $t): FakeIdToken => $t->with('azp', 'another-client'), FailureReason::AUDIENCE_MISMATCH],
            'at_hash wrong'           => [[], static fn (FakeIdToken $t): FakeIdToken => $t->with('at_hash', 'wrong'), FailureReason::AT_HASH_MISMATCH],
            'at_hash another'         => [[], static fn (FakeIdToken $t): FakeIdToken => $t->accessTokenHash('another-access-token'), FailureReason::AT_HASH_MISMATCH],
            'sub an integer'          => [[], static fn (FakeIdToken $t): FakeIdToken => $t->with('sub', 1), FailureReason::ID_TOKEN_INVALID],
            'auth_time in the future' => [
                [],
                static fn (FakeIdToken $t): FakeIdToken => $t->with('auth_time', self::issuedAt($t) + self::SKEW + 1),
                FailureReason::ASSERTION_EXPIRED,
            ],
            'auth_time too old for max_age' => [
                ['max_age' => 300],
                static fn (FakeIdToken $t): FakeIdToken => $t->with('auth_time', self::issuedAt($t) - 300 - self::SKEW - 1),
                FailureReason::AUTHENTICATION_EXPIRED,
            ],
            'auth_time missing with max_age' => [['max_age' => 300], static fn (FakeIdToken $t): FakeIdToken => $t->without('auth_time'), FailureReason::ID_TOKEN_INVALID],
        ];
    }

    /**
     * An ID token with a wrong claim is refused through the callback.
     *
     * @param  array<string, mixed>  $settings
     * @param  \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken  $tailor
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideWrongClaims')]
    public function testAWrongClaimIsRefusedThroughTheCallback(array $settings, \Closure $tailor, FailureReason $reason): void
    {
        $connection = $this->honestConnection($settings);
        $grant      = $this->granted($connection, $tailor);
        $request    = $this->latestRequest();

        $this->startRecordingEvents();

        $this->assertRefused($this->receiveCallback($connection, $grant), $reason, $request);
        $this->assertEventSequence([FlowFailed::class]);
        self::assertSame([FetchPurpose::TOKEN], $this->fetchPurposes());
    }

    /**
     * Rows of `[claim, as a list]`: a string claim written as a huge number.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideNumbersForStrings(): iterable
    {
        yield from [
            'iss'         => ['iss', false],
            'sub'         => ['sub', false],
            'aud'         => ['aud', false],
            'an aud item' => ['aud', true],
            'azp'         => ['azp', false],
            'nonce'       => ['nonce', false],
            'at_hash'     => ['at_hash', false],
            'email'       => ['email', false],
            'acr'         => ['acr', false],
            'sid'         => ['sid', false],
            'an amr item' => ['amr', true],
        ];
    }

    /**
     * A number too large for an integer is never a string claim.
     *
     * @param  string  $claim
     * @param  bool  $list
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideNumbersForStrings')]
    public function testANumberIsNeverAStringClaim(string $claim, bool $list): void
    {
        $connection = $this->honestConnection();
        $grant      = $this->granted($connection, static function (FakeIdToken $t) use ($claim, $list): FakeIdToken {
            $json = (string) json_encode($t->with($claim, $list ? ['the-number'] : 'the-number')->claims(), JSON_UNESCAPED_SLASHES);

            return $t->withPayloadJson(str_replace('"the-number"', '123456789012345678901234567890', $json));
        });
        $request = $this->latestRequest();

        $this->startRecordingEvents();

        $this->assertRefused($this->receiveCallback($connection, $grant), FailureReason::ID_TOKEN_INVALID, $request);
        $this->assertEventSequence([FlowFailed::class]);
        self::assertSame([FetchPurpose::TOKEN], $this->fetchPurposes());
    }

    /**
     * The same digits written as a string are a subject like any other.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheSameDigitsAsAStringAreASubject(): void
    {
        $connection = $this->honestConnection();
        $grant      = $this->granted($connection, static fn (FakeIdToken $t): FakeIdToken => $t->with('sub', '123456789012345678901234567890'));

        self::assertTrue($this->receiveCallback($connection, $grant)->isCompleted());
    }

    /**
     * Rows of `[auth_time, reason]`; the start less the skew is 70 seconds ago.
     *
     * @return iterable<string, array{0: ?int, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideReauthentications(): iterable
    {
        yield from [
            'as it completes'       => [0, null],
            'at the skew'           => [-60, null],
            'at the start and skew' => [-70, null],
            'before it'             => [-71, FailureReason::AUTHENTICATION_EXPIRED],
            'long before it'        => [-3600, FailureReason::AUTHENTICATION_EXPIRED],
            'absent'                => [null, FailureReason::ID_TOKEN_INVALID],
            'past now and the skew' => [61, FailureReason::ASSERTION_EXPIRED],
        ];
    }

    /**
     * A `reauthenticate` is held to `auth_time`.
     *
     * @param  ?int  $authenticatedAgo
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideReauthentications')]
    public function testAReauthenticationIsHeldToAuthTime(?int $authenticatedAgo, ?FailureReason $reason): void
    {
        $this->assertReauthentication(10, $authenticatedAgo, $reason);
    }

    /**
     * Rows of `[auth_time, reason]`; the start less the skew is 30 seconds ago.
     *
     * @return iterable<string, array{0: int, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideReauthenticationsAfterTheClockMoved(): iterable
    {
        yield from [
            'at the start less the skew' => [-30, null],
            'a second before it'         => [-31, FailureReason::AUTHENTICATION_EXPIRED],
        ];
    }

    /**
     * With the clock moved back since the start the rule is unchanged.
     *
     * @param  int  $authenticatedAgo
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideReauthenticationsAfterTheClockMoved')]
    public function testTheStartAloneDecidesAfterTheClockMovedBack(int $authenticatedAgo, ?FailureReason $reason): void
    {
        $this->assertReauthentication(-30, $authenticatedAgo, $reason);
    }

    /**
     * Rows of `[auth_time, reason]`; the start less the skew is 360s ago.
     *
     * @return iterable<string, array{0: int, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideSlowCallbacks(): iterable
    {
        yield from [
            'as the request started'   => [-300, null],
            'at its start and skew'    => [-360, null],
            'a second before it'       => [-361, FailureReason::AUTHENTICATION_EXPIRED],
            'just as the callback ran' => [0, null],
        ];
    }

    /**
     * A slow callback is never refused for its own delay.
     *
     * @param  int  $authenticatedAgo
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideSlowCallbacks')]
    public function testASlowCallbackIsNeverRefusedForItsOwnDelay(int $authenticatedAgo, ?FailureReason $reason): void
    {
        $this->assertReauthentication(300, $authenticatedAgo, $reason);
    }

    /**
     * Expired keys refuse a callback until an administrator refreshes them.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testAnExpiredConnectionIsRecoveredByAnAdministratorNotACallback(): void
    {
        config()->set('sso.features.metadata_refresh', false);

        $connection = $this->honestConnection(['metadata_refresh' => false]);

        $connection->forceFill(['jwks_fetched_at' => $this->clock->now()->subSeconds(2592000 - 1)])->save();

        $this->provider->publish(self::next())->signWith(self::next());

        $grant   = $this->granted($connection);
        $request = $this->latestRequest();

        $this->clock->advance(1);
        $this->startRecordingEvents();

        $this->assertRefused($this->receiveCallback($connection, $grant), FailureReason::METADATA_EXPIRED, $request);
        self::assertSame([], $this->fetchPurposes());
        self::assertNull($connection->fresh()?->jwks_refetch_at);

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $refreshed = app(MetadataRefresher::class)->refreshNow(
            $connection->tenant_id,
            $connection->id,
            new Caller(new IdentityReference('App\Models\User', '42')),
            Clients::browser(),
        );

        self::assertTrue($refreshed->isRefreshed());
        self::assertTrue($this->receiveCallback($connection, $this->granted($connection))->isCompleted());
    }

    /**
     * Refetched keys past their stale limit refuse until a refresh succeeds.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testKeysPastTheirLimitRefuseACallbackUntilARefreshSucceeds(): void
    {
        config()->set('sso.features.metadata_refresh', true);

        $connection = $this->honestConnection(['metadata_refresh' => true]);

        $connection->forceFill(['jwks_fetched_at' => $this->clock->now()->subSeconds(2592000 - 1)])->save();

        $grant   = $this->granted($connection);
        $request = $this->latestRequest();

        $this->clock->advance(1);
        $this->startRecordingEvents();

        $this->assertRefused($this->receiveCallback($connection, $grant), FailureReason::METADATA_EXPIRED, $request);
        self::assertSame([], $this->fetchPurposes());

        $refreshed = app(MetadataRefresher::class)->refreshQueued($connection->id, Clients::browser());

        self::assertTrue($refreshed->isRefreshed());
        self::assertTrue($this->receiveCallback($connection, $this->granted($connection))->isCompleted());
    }

    /**
     * An honest token verifies, with nothing fetched.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnHonestTokenVerifies(): void
    {
        $connection = $this->honestConnection();
        $grant      = $this->granted($connection);
        $request    = $this->latestRequest();

        $this->startRecordingEvents();

        $result = $this->receiveCallback($connection, $grant);

        self::assertSame(['completed', null, self::REDIRECT_URI, $request->reference], [$result->status->value, $result->reason, $result->redirectUri, $result->reference?->value]);
        self::assertNotNull($result->handoff);
        $this->assertEventSequence([ResultVerified::class, ResultUnlinked::class, HandoffIssued::class]);
        $this->assertNoFailure();
        self::assertSame([], $this->jwksFetches());
        self::assertSame(1, HandoffCode::query()->count());
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Rows of `[algorithm, key]`: every algorithm family the allow-list holds.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideHonestAlgorithms(): iterable
    {
        yield from [
            'RS256 with k1' => ['RS256', 'rsa'],
            'RS256 with k2' => ['RS256', 'rsaWithAlgorithm'],
            'PS256 with k1' => ['PS256', 'rsa'],
            'ES256 with e1' => ['ES256', 'ec'],
        ];
    }

    /**
     * A token of each allowed algorithm verifies.
     *
     * @param  string  $algorithm
     * @param  string  $key
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideHonestAlgorithms')]
    public function testEachAllowedAlgorithmVerifies(string $algorithm, string $key): void
    {
        $connection = $this->honestConnection();
        $signing    = match ($key) {
            'rsa'              => self::hostile()->rsa,
            'rsaWithAlgorithm' => self::hostile()->rsaWithAlgorithm,
            default            => self::hostile()->ec,
        };

        $this->provider->signWith($signing, $algorithm);

        self::assertTrue($this->receiveCallback($connection, $this->granted($connection))->isCompleted());
        self::assertSame([], $this->jwksFetches());
    }

    /**
     * An additive rotation verifies after one refetch and voids nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnAdditiveRotationVerifiesAfterOneRefetch(): void
    {
        $connection = $this->honestConnection();
        $version    = (int) $connection->fresh()?->trust_version;

        $this->provider->publish(self::next())->signWith(self::next());

        $grant   = $this->granted($connection);
        $request = $this->latestRequest();

        $this->startRecordingEvents();

        $result = $this->receiveCallback($connection, $grant);

        self::assertTrue($result->isCompleted());
        $this->assertEventSequence([JwksRefreshed::class, ResultVerified::class, ResultUnlinked::class, HandoffIssued::class]);

        $refreshed = $this->recordedEvents()[0];

        self::assertInstanceOf(JwksRefreshed::class, $refreshed);
        self::assertSame([1, 0, false], [$refreshed->keysAdded, $refreshed->keysRemoved, $refreshed->trustChanged]);
        self::assertSame($version, $connection->fresh()?->trust_version);
        self::assertNull($request->fresh()?->voided_at);
        self::assertCount(1, $this->jwksFetches());

        self::assertTrue($this->receiveCallback($connection, $this->granted($connection))->isCompleted());
        self::assertCount(1, $this->jwksFetches());
    }

    /**
     * A removing rotation voids other flows but lets its own callback finish.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARemovingRotationLetsItsOwnCallbackFinish(): void
    {
        $connection = $this->honestConnection();
        $version    = (int) $connection->fresh()?->trust_version;

        $this->provider->unpublish('k1')->publish(self::next())->signWith(self::next());

        $grant   = $this->granted($connection);
        $request = $this->latestRequest();

        $this->startRecordingEvents();

        $result = $this->receiveCallback($connection, $grant);

        self::assertTrue($result->isCompleted());
        self::assertNotNull($result->handoff);
        $this->assertEventSequence([JwksRefreshed::class, ResultVerified::class, ResultUnlinked::class, HandoffIssued::class]);
        $this->assertNoFailure();

        $refreshed = $this->recordedEvents()[0];

        self::assertInstanceOf(JwksRefreshed::class, $refreshed);
        self::assertSame([1, 1, true], [$refreshed->keysAdded, $refreshed->keysRemoved, $refreshed->trustChanged]);
        self::assertNull($request->fresh()?->voided_at);
        self::assertNotNull($request->fresh()?->completed_at);
        self::assertSame($version + 1, $connection->fresh()?->trust_version);
        self::assertCount(1, $this->jwksFetches());
    }

    /**
     * Rows of `[flag]`: an `email_verified` that is not a JSON boolean.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideNonBooleanFlags(): iterable
    {
        yield from [
            'the string true'  => ['true'],
            'the string false' => ['false'],
            'one'              => [1],
            'an object'        => [['value' => true]],
            'null'             => [null],
        ];
    }

    /**
     * A non-boolean `email_verified` does not refuse the sign-in.
     *
     * @param  mixed  $flag
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideNonBooleanFlags')]
    public function testANonBooleanEmailVerifiedDoesNotRefuseTheSignIn(mixed $flag): void
    {
        $connection = $this->honestConnection();
        $grant      = $this->granted($connection, static fn (FakeIdToken $t): FakeIdToken => $t->with('email', 'person@example.test')->with('email_verified', $flag));
        $result     = $this->receiveCallback($connection, $grant);

        self::assertTrue($result->isCompleted());
        self::assertSame([], $this->jwksFetches());
        self::assertSame(['email' => 'person@example.test', 'verified' => null, 'source' => 'id_token'], self::handedOff()->assertedEmail?->toArray());
        self::assertNull(self::handedOff()->linkingEmail);
    }

    /**
     * A non-boolean UserInfo `email_verified` does not refuse the sign-in.
     *
     * @param  mixed  $flag
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideNonBooleanFlags')]
    public function testANonBooleanUserInfoFlagDoesNotRefuseTheSignIn(mixed $flag): void
    {
        $connection = $this->honestConnection(['fetch_userinfo' => true, 'userinfo_endpoint' => $this->provider->endpoint('userinfo')]);

        $this->provider->withUserInfo(['email' => 'person@example.test', 'email_verified' => $flag]);

        $result = $this->receiveCallback($connection, $this->granted($connection));

        self::assertTrue($result->isCompleted());
        self::assertContains(FetchPurpose::USERINFO, $this->fetchPurposes());
        self::assertSame(['email' => 'person@example.test', 'verified' => null, 'source' => 'userinfo'], self::handedOff()->assertedEmail?->toArray());
        self::assertNull(self::handedOff()->linkingEmail);
    }

    /**
     * A boolean `email_verified` is the evidence it says; only true links.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testABooleanEmailVerifiedThroughTheWholePath(): void
    {
        $connection = $this->honestConnection();

        foreach ([true, false] as $flag) {

            $grant = $this->granted($connection, static fn (FakeIdToken $t): FakeIdToken => $t->with('email', 'person@example.test')->with('email_verified', $flag));

            self::assertTrue($this->receiveCallback($connection, $grant)->isCompleted());
            self::assertSame($flag, self::handedOff()->assertedEmail?->toArray()['verified']);

            HandoffCode::query()->delete();
        }
    }

    /**
     * A key replaced under a known `kid` is not refetched.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAKeyReplacedUnderItsKidIsNotFetched(): void
    {
        $connection = $this->honestConnection();
        $grant      = $this->granted($connection, static fn (FakeIdToken $t): FakeIdToken => $t->signedWith(self::next()->withKid('k1'), 'RS256'));

        $this->startRecordingEvents();

        $this->assertRefused($this->receiveCallback($connection, $grant), FailureReason::SIGNATURE_INVALID, $this->latestRequest());
        self::assertSame([], $this->jwksFetches());
    }

    /**
     * Assert how a reauthentication ends for the clock move and `auth_time`.
     *
     * @param  int  $moved
     * @param  ?int  $authenticatedAgo
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function assertReauthentication(int $moved, ?int $authenticatedAgo, ?FailureReason $reason): void
    {
        $this->app?->instance(ReauthenticationSessions::class, new class implements ReauthenticationSessions {
            /**
             * Answer that the identity is signed in on the session.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  string  $application
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            #[\Override]
            public function standing(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection): SessionStanding
            {
                unset($identity, $sessionId, $application, $connection);

                return SessionStanding::SIGNED_IN;
            }

            /**
             * The identity's session, locked; as `standing()` answers.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  string  $application
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  string  $linkId
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            #[\Override]
            public function lockedStanding(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection, string $linkId): SessionStanding
            {
                unset($linkId);

                return $this->standing($identity, $sessionId, $application, $connection);
            }

            /**
             * Renew nothing.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  \Carbon\CarbonImmutable  $authenticatedAt
             * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
             * @return void
             */
            #[\Override]
            public function renewAuthentication(IdentityReference $identity, string $sessionId, CarbonImmutable $authenticatedAt, ?AcceptedEvidence $evidence): void
            {
                unset($identity, $sessionId, $authenticatedAt, $evidence);
            }
        });

        $connection = $this->honestConnection();
        $url        = $this->startUrl($connection, Purpose::REAUTHENTICATE, new IdentityReference('App\Models\User', '42'), 'session-1');

        $this->app?->instance(Linker::class, new FixedLinker(new IdentityReference('App\Models\User', '42')));
        $request = $this->latestRequest();

        $this->clock->advance($moved);

        $tailor = static fn (FakeIdToken $t): FakeIdToken => $authenticatedAgo === null ? $t->without('auth_time') : $t->with('auth_time', self::issuedAt($t) + $authenticatedAgo);
        $grant  = $this->provider->authorize($url, $tailor);

        $this->startRecordingEvents();

        $result = $this->receiveCallback($connection, $grant);

        if ($reason === null) {
            self::assertTrue($result->isCompleted());
            $this->assertEventSequence([ResultVerified::class, HandoffIssued::class]);

            return;
        }

        $this->assertRefused($result, $reason, $request);
        $this->assertEventSequence([FlowFailed::class]);
    }

    /**
     * Assert an unknown `kid` is refused, and count the JWKS requests.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $kid
     * @param  int  $fetches
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function assertUnknownKidIsRefused(Connection $connection, string $kid, int $fetches): void
    {
        $grant  = $this->granted($connection, static fn (FakeIdToken $honest): FakeIdToken => $honest->withHeader('kid', $kid));
        $result = $this->receiveCallback($connection, $grant);

        self::assertSame([true, FailureReason::SIGNATURE_INVALID], [$result->isFailed(), $result->reason]);
        self::assertCount($fetches, $this->jwksFetches());
    }

    /**
     * Assert the completion was refused for the reason with one failure.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  int  $completed
     * @return void
     */
    private function assertRefused(CompletionResult $result, FailureReason $reason, AuthorizationRequest $request, int $completed = 1): void
    {
        self::assertSame(
            ['failed', $reason, self::REDIRECT_URI, $request->reference],
            [$result->status->value, $result->reason, $result->redirectUri, $result->reference?->value],
        );
        self::assertNull($result->handoff);
        self::assertSame($request->reference, $this->assertExactlyOneFailure(Flow::CALLBACK, $reason)->context()->requestReference);

        $row = $request->fresh();

        self::assertNotNull($row?->consumed_at);
        self::assertNotNull($row->completed_at);
        self::assertSame(0, HandoffCode::query()->count());
        self::assertSame(0, Link::query()->count());
        self::assertSame($completed, AuthorizationRequest::query()->whereNotNull('completed_at')->count());
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
        return app(CompletionService::class)->complete(CompletionEndpoint::CALLBACK, $connection->id, new CompletionRequest('GET', $grant->query(), []), Clients::browser());
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
        return $this->provider->authorize($this->startUrl($connection), $tailor);
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
        $started = app(AuthorizationRequestService::class)->start(
            'web',
            $purpose,
            $connection->id,
            Clients::browser(),
            null,
            $identity === null ? null : new Caller($identity, $session),
        );

        self::assertTrue($started->isStarted());

        $this->reference = (string) $started->reference?->value;

        return (string) $started->navigation?->url();
    }

    /**
     * The request started last, by reference, since ids share an instant.
     *
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function latestRequest(): AuthorizationRequest
    {
        return AuthorizationRequest::query()->where('reference', $this->reference)->firstOrFail();
    }

    /**
     * What each request made was for, in order: every fetch of the flow.
     *
     * @return list<\SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose>
     */
    private function fetchPurposes(): array
    {
        return array_map(static fn (FetchRequest $request): FetchPurpose => $request->purpose, $this->fetcher->requests());
    }

    /**
     * The JWKS requests made, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Fetching\FetchRequest>
     */
    private function jwksFetches(): array
    {
        return array_values(array_filter($this->fetcher->requests(), static fn (FetchRequest $request): bool => $request->purpose === FetchPurpose::JWKS));
    }

    /**
     * The connection the case is judged by.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\HostileIdToken  $case
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function hostileConnection(HostileIdToken $case): Connection
    {
        foreach ($this->provider->jwks()['keys'] as $published) {
            $this->provider->unpublish(is_string($published['kid'] ?? null) ? $published['kid'] : null);
        }

        foreach ($case->jwks['keys'] as $jwk) {
            $this->provider->publishJwk($jwk);
        }

        return $this->connectionOf(['id_token_algorithms' => $case->algorithms], $case->stage === 'jwks_refused' ? null : self::stored($case->jwks, $case->algorithms));
    }

    /**
     * The verified result the code issued carries, as a redemption reads it.
     *
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     *
     * @throws \UnexpectedValueException
     */
    private static function handedOff(): VerifiedResult
    {
        /** @var array<string, mixed> $stored */
        $stored = json_decode(app(SecretEncrypter::class)->decrypt(HandoffCode::query()->sole()->result), true);

        return VerifiedResult::restore($stored);
    }

    /**
     * A connection of the honest allow-list with the settings given.
     *
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function honestConnection(array $settings = []): Connection
    {
        $this->provider->unpublish('k1');

        foreach (self::hostile()->jwks()['keys'] as $jwk) {
            $this->provider->publishJwk($jwk);
        }

        return $this->connectionOf(['id_token_algorithms' => HostileIdTokens::ALGORITHMS, ...$settings], self::stored(self::hostile()->jwks(), HostileIdTokens::ALGORITHMS));
    }

    /**
     * An enabled connection of the provider, with the settings and keys given.
     *
     * @param  array<string, mixed>  $settings
     * @param  ?string  $jwks
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connectionOf(array $settings, ?string $jwks): Connection
    {
        return $this->makeConnection([
            'enabled'  => true,
            'jwks'     => $jwks,
            'secrets'  => app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret(FakeOpenIdProvider::CLIENT_SECRET)]),
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
     * The stored form of the JWKS, read under the allow-list.
     *
     * @param  array{keys: list<array<string, mixed>>}  $jwks
     * @param  list<string>  $algorithms
     * @return ?string
     */
    private static function stored(array $jwks, array $algorithms): ?string
    {
        return ProviderKeySet::read((string) json_encode($jwks), AlgorithmAllowList::of($algorithms), 65536, 50)?->toStored();
    }

    /**
     * The token's `iat`: the clock's now when the provider issued it.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken  $token
     * @return int
     */
    private static function issuedAt(FakeIdToken $token): int
    {
        $issued = $token->claims()['iat'] ?? null;

        return is_int($issued) ? $issued : 0;
    }

    /**
     * Each case's JWKS, allow-list, stage and reason, read once.
     *
     * @return array<string, \SineMacula\Laravel\Sso\Testing\Oidc\HostileIdToken>
     */
    private static function cases(): array
    {
        $claims = ['iss' => FakeOpenIdProvider::ISSUER, 'sub' => FakeOpenIdProvider::SUBJECT, 'aud' => FakeOpenIdProvider::CLIENT_ID, 'iat' => 1, 'exp' => 2];

        return self::$cases ??= self::hostile()->cases($claims, self::SKEW);
    }

    /**
     * The cases' keys, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\HostileIdTokens
     */
    private static function hostile(): HostileIdTokens
    {
        return self::$hostile ??= new HostileIdTokens;
    }

    /**
     * The provider's next key, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function next(): FakeSigningKey
    {
        return self::$next ??= FakeSigningKey::rsa('next');
    }
}
