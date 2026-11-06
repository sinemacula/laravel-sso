<?php

declare(strict_types = 1);

namespace Tests\Integration\Completion;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokenValidator;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Consecutive OIDC callbacks in one process, as a worker under Octane or a
 * queue serves them (SSO-11.2): two tenants, each a connection of its own
 * provider, with different issuers, client ids, allow-lists, trusted audiences
 * and keys under one `kid`. The services are resolved once and kept. Nothing of
 * one callback reaches the next: not a key, an allow-list, an audience, a
 * `max_age`, a clock skew or a result.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(IdTokenValidator::class)]
final class OidcWorkerIsolationTest extends TestCase
{
    use CapturesLogs, UsesConnections;

    /** @var string The `kid` both providers sign under. */
    private const string SHARED_KID = 'shared-kid';

    /** @var string The first tenant. */
    private const string TENANT_A = 'tenant-a';

    /** @var string The second tenant. */
    private const string TENANT_B = 'tenant-b';

    /** @var string The first connection's client id. */
    private const string CLIENT_A = 'client-a';

    /** @var string The second connection's client id. */
    private const string CLIENT_B = 'client-b';

    /** @var string The audience the first connection trusts. */
    private const string AUDIENCE_A = 'api-a';

    /** @var string The audience the second connection trusts. */
    private const string AUDIENCE_B = 'api-b';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The first provider's key, made once. */
    private static ?FakeSigningKey $keyA = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The second provider's key, made once. */
    private static ?FakeSigningKey $keyB = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher both providers answer on. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The first connection's provider. */
    private FakeOpenIdProvider $providerA;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The second connection's provider. */
    private FakeOpenIdProvider $providerB;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The first connection: RS256 alone. */
    private Connection $connectionA;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The second connection: PS256 alone, with a `max_age`. */
    private Connection $connectionB;

    /** @var \SineMacula\Laravel\Sso\Completion\CompletionService The service kept for every callback. */
    private CompletionService $completions;

    /** @var \SineMacula\Laravel\Sso\Flows\AuthorizationRequestService The service kept for every start. */
    private AuthorizationRequestService $starts;

    /**
     * Bind a fixed clock, the fake fetcher and a request from a client, switch
     * OIDC on, create the tables and both connections and resolve the services
     * once. The default handoff store is left in place.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $clock         = new FixedClock('2026-11-01T09:30:00Z');
        $this->fetcher = new FakeFetcher;

        $this->app?->instance(Clock::class, $clock);
        $this->app?->instance(Fetcher::class, $this->fetcher);
        $this->app?->instance('request', Request::create('https://sp.example.test/auth/sso/connections/x/callback', 'GET', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.oidc', true);
        config()->set('sso.clock.skew_seconds', 60);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->usePackageTables();

        $this->captureLogs();

        $this->providerA = (new FakeOpenIdProvider('https://op-a.example.test', self::keyA(), $clock))
            ->register(self::CLIENT_A, 'client_secret_basic', 'secret-a')
            ->serve($this->fetcher);
        $this->providerB = (new FakeOpenIdProvider('https://op-b.example.test', self::keyB(), $clock))
            ->signWith(self::keyB(), 'PS256')
            ->register(self::CLIENT_B, 'client_secret_basic', 'secret-b')
            ->serve($this->fetcher);

        $settingsA = ['id_token_algorithms' => ['RS256'], 'trusted_audiences' => [self::AUDIENCE_A]];
        $settingsB = ['id_token_algorithms' => ['PS256'], 'trusted_audiences' => [self::AUDIENCE_B], 'max_age' => 300];

        $this->connectionA = $this->connection($this->providerA, self::TENANT_A, self::CLIENT_A, 'secret-a', self::keyA(), $settingsA);
        $this->connectionB = $this->connection($this->providerB, self::TENANT_B, self::CLIENT_B, 'secret-b', self::keyB(), $settingsB);

        $this->completions = app(CompletionService::class);
        $this->starts      = app(AuthorizationRequestService::class);
    }

    /**
     * Consecutive verified callbacks each answer their own result: the tenant,
     * connection, issuer and subject of the handoff they stored, in turn.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEachResultIsItsOwn(): void
    {
        $turns = [
            ['A', 'person-a-1'],
            ['B', 'person-b-1'],
            ['A', 'person-a-2'],
            ['B', 'person-b-2'],
        ];

        foreach ($turns as [$side, $subject]) {

            $reference = '';
            $result    = $this->flow($side, static fn (FakeIdToken $t): FakeIdToken => $t->with('sub', $subject), $reference);

            self::assertTrue($result->isCompleted(), $subject);

            $stored = $this->storedResult($reference);

            self::assertSame([
                $subject,
                $this->providerOf($side)->issuer,
                $this->connectionOf($side)->id,
                $side === 'A' ? self::TENANT_A : self::TENANT_B,
            ], [$stored['subject'], $stored['issuer'], $stored['connection_id'], $stored['tenant_id']]);
        }

        self::assertSame(4, HandoffCode::query()->count());
        self::assertSame([], $this->jwksFetches());
    }

    /**
     * Both providers sign under one `kid`, and each connection holds its own
     * key under it: a token of one, for the other, never verifies, whichever
     * went first, with nothing fetched.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAKeyNeverLeaks(): void
    {
        $turn = function (string $side, ?FakeSigningKey $key, string $algorithm, ?FailureReason $reason): void {
            $tailor = $key === null ? null : static fn (FakeIdToken $t): FakeIdToken => $t->signedWith($key, $algorithm);

            self::assertSame($reason, $this->flow($side, $tailor)->reason);
        };

        $turn('A', null, 'RS256', null);
        $turn('B', self::keyA(), 'PS256', FailureReason::SIGNATURE_INVALID);
        $turn('B', null, 'PS256', null);
        $turn('A', self::keyB(), 'RS256', FailureReason::SIGNATURE_INVALID);
        $turn('A', null, 'RS256', null);

        self::assertSame([], $this->jwksFetches());
    }

    /**
     * Each connection's allow-list stands, read afresh on each callback: an
     * algorithm the last callback verified is refused on the next, with nothing
     * fetched.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnAllowListNeverLeaks(): void
    {
        self::assertTrue($this->flow('B')->isCompleted());
        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->flow('A', static fn (FakeIdToken $t): FakeIdToken => $t->signedWith(self::keyA(), 'PS256'))->reason);
        self::assertTrue($this->flow('A')->isCompleted());
        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->flow('B', static fn (FakeIdToken $t): FakeIdToken => $t->signedWith(self::keyB(), 'RS256'))->reason);
        self::assertTrue($this->flow('B')->isCompleted());
        self::assertSame([], $this->jwksFetches());
    }

    /**
     * Each connection's issuer and client id stand: a token naming the last
     * callback's is refused on the next.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnIssuerAndAClientNeverLeak(): void
    {
        self::assertTrue($this->flow('B')->isCompleted());
        self::assertSame(FailureReason::ISSUER_MISMATCH, $this->flow('A', fn (FakeIdToken $t): FakeIdToken => $t->with('iss', $this->providerB->issuer))->reason);
        self::assertSame(FailureReason::AUDIENCE_MISMATCH, $this->flow('A', static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', self::CLIENT_B))->reason);
        self::assertTrue($this->flow('A')->isCompleted());
        self::assertSame(FailureReason::ISSUER_MISMATCH, $this->flow('B', fn (FakeIdToken $t): FakeIdToken => $t->with('iss', $this->providerA->issuer))->reason);
    }

    /**
     * Each connection's trusted audiences stand: the other's is untrusted, on
     * the very next callback.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTrustedAudiencesNeverLeak(): void
    {
        $audiences = static function (string $client, string $audience): \Closure {
            $claims = ['aud' => [$client, $audience], 'azp' => $client];

            return static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', $claims['aud'])->with('azp', $claims['azp']);
        };

        self::assertTrue($this->flow('A', $audiences(self::CLIENT_A, self::AUDIENCE_A))->isCompleted());
        self::assertSame(FailureReason::AUDIENCE_MISMATCH, $this->flow('B', $audiences(self::CLIENT_B, self::AUDIENCE_A))->reason);
        self::assertTrue($this->flow('B', $audiences(self::CLIENT_B, self::AUDIENCE_B))->isCompleted());
        self::assertSame(FailureReason::AUDIENCE_MISMATCH, $this->flow('A', $audiences(self::CLIENT_A, self::AUDIENCE_B))->reason);
        self::assertTrue($this->flow('A', $audiences(self::CLIENT_A, self::AUDIENCE_A))->isCompleted());
    }

    /**
     * One connection's `max_age` is the other's none: a long-past `auth_time`
     * passes on the one with none, on either side of a refusal by the other.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAMaxAgeNeverLeaks(): void
    {
        $old = static fn (FakeIdToken $t): FakeIdToken => $t->with('auth_time', 1);

        self::assertTrue($this->flow('A', $old)->isCompleted());
        self::assertSame(FailureReason::AUTHENTICATION_EXPIRED, $this->flow('B', $old)->reason);
        self::assertTrue($this->flow('A', $old)->isCompleted());
    }

    /**
     * The clock skew is read on each callback: a change to it between two
     * callbacks is seen by the second, and none is kept from the first.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClockSkewNeverLeaks(): void
    {
        $ahead = static fn (FakeIdToken $t): FakeIdToken => $t->with('iat', self::issuedAt($t) + 30);

        self::assertTrue($this->flow('A', $ahead)->isCompleted());

        config()->set('sso.clock.skew_seconds', 0);

        self::assertSame(FailureReason::ASSERTION_EXPIRED, $this->flow('B', $ahead)->reason);
        self::assertSame(FailureReason::ASSERTION_EXPIRED, $this->flow('A', $ahead)->reason);

        config()->set('sso.clock.skew_seconds', 60);

        self::assertTrue($this->flow('B', $ahead)->isCompleted());
    }

    /**
     * A refused callback leaves nothing for the next: its subject and handoff
     * are nowhere, and the next verified one answers its own.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARefusalLeavesNothingForTheNext(): void
    {
        $refused = static fn (FakeIdToken $t): FakeIdToken => $t->with('sub', 'person-refused')->with('aud', 'nobody');

        self::assertSame(FailureReason::AUDIENCE_MISMATCH, $this->flow('A', $refused)->reason);

        $reference = '';

        self::assertTrue($this->flow('B', static fn (FakeIdToken $t): FakeIdToken => $t->with('sub', 'person-b'), $reference)->isCompleted());

        $stored = $this->storedResult($reference);

        self::assertSame(['person-b', self::TENANT_B], [$stored['subject'], $stored['tenant_id']]);
        self::assertSame(1, HandoffCode::query()->count());
    }

    /**
     * A refetch for one connection fetches its own JWKS and writes its own row:
     * the other's keys and cooldown stay as they were.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARefetchNeverReachesTheOtherConnection(): void
    {
        $before = $this->connectionB->fresh();

        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->flow('A', static fn (FakeIdToken $t): FakeIdToken => $t->withHeader('kid', 'unknown'))->reason);

        $fetches = $this->jwksFetches();
        $after   = $this->connectionB->fresh();

        self::assertCount(1, $fetches);
        self::assertSame($this->providerA->endpoint('jwks'), $fetches[0]->url);
        self::assertSame([$before?->jwks, $before?->jwks_version, $before?->jwks_refetch_at], [$after?->jwks, $after?->jwks_version, $after?->jwks_refetch_at]);
        self::assertNotNull($this->connectionA->fresh()?->jwks_refetch_at);

        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->flow('B', static fn (FakeIdToken $t): FakeIdToken => $t->withHeader('kid', 'unknown'))->reason);

        $fetches = $this->jwksFetches();

        self::assertCount(2, $fetches);
        self::assertSame($this->providerB->endpoint('jwks'), $fetches[1]->url);
    }

    /**
     * Start a flow through the side's connection, have its provider grant it
     * and complete at its callback, through the services kept. The reference
     * given is set to the request's.
     *
     * @param  string  $side
     * @param  ?\Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken  $tailor
     * @param  string  $reference
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \Random\RandomException
     */
    private function flow(string $side, ?\Closure $tailor = null, string &$reference = ''): CompletionResult
    {
        $connection = $this->connectionOf($side);
        $started    = $this->starts->start('web', Purpose::SIGN_IN, $connection->id, Clients::browser());

        self::assertTrue($started->isStarted());

        $reference = (string) $started->reference?->value;
        $grant     = $this->providerOf($side)->authorize((string) $started->navigation?->url(), $tailor);

        return $this->completions->complete(CompletionEndpoint::CALLBACK, $connection->id, new CompletionRequest('GET', $grant->query(), []), Clients::browser());
    }

    /**
     * The result the handoff of the request stored, decrypted.
     *
     * @param  string  $reference
     * @return array<string, mixed>
     */
    private function storedResult(string $reference): array
    {
        $code = HandoffCode::query()->where('request_reference', $reference)->firstOrFail();

        /** @var array<string, mixed> */
        return json_decode(app(SecretEncrypter::class)->decrypt($code->result), true, 16, JSON_THROW_ON_ERROR);
    }

    /**
     * The side's connection.
     *
     * @param  string  $side
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connectionOf(string $side): Connection
    {
        return $side === 'A' ? $this->connectionA : $this->connectionB;
    }

    /**
     * The side's provider.
     *
     * @param  string  $side
     * @return \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider
     */
    private function providerOf(string $side): FakeOpenIdProvider
    {
        return $side === 'A' ? $this->providerA : $this->providerB;
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
     * An enabled connection of the provider, of the tenant, the client and the
     * secret, storing its key.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @param  string  $tenant
     * @param  string  $client
     * @param  string  $secret
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $key
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connection(FakeOpenIdProvider $provider, string $tenant, string $client, string $secret, FakeSigningKey $key, array $settings): Connection
    {
        $jwks = (string) json_encode(['keys' => [$key->jwk()]]);

        return $this->makeConnection([
            'tenant_id' => $tenant,
            'enabled'   => true,
            'jwks'      => ProviderKeySet::read($jwks, AlgorithmAllowList::of(['RS256', 'PS256']), 65536, 50)?->toStored(),
            'secrets'   => app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret($secret)]),
            'settings'  => [
                'issuer'                 => $provider->issuer,
                'authorization_endpoint' => $provider->endpoint('authorization'),
                'token_endpoint'         => $provider->endpoint('token'),
                'jwks_uri'               => $provider->endpoint('jwks'),
                'client_id'              => $client,
                ...$settings,
            ],
        ]);
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
     * The first provider's key, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function keyA(): FakeSigningKey
    {
        return self::$keyA ??= FakeSigningKey::rsa(self::SHARED_KID);
    }

    /**
     * The second provider's key, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function keyB(): FakeSigningKey
    {
        return self::$keyB ??= FakeSigningKey::rsa(self::SHARED_KID);
    }
}
