<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\JwksRefreshed;
use SineMacula\Laravel\Sso\Events\JwksRefreshFailed;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Metadata\JwksRefetcher;
use SineMacula\Laravel\Sso\Metadata\ProviderKeys;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Enums\KeySelectionOutcome;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\TransitionReceipt;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use SineMacula\Laravel\Sso\Testing\Oidc\JwsSigner;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the refetch of a JWKS on an unknown `kid` (SSO-7.3),
 * through the public selection and the refetcher itself with the fake provider:
 * the cooldown claimed before the fetch, at most one fetch per cooldown, to the
 * second; a failed fetch consuming it; the compare and set; an exact
 * replacement of the keys; and when it voids and raises the trust version.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-import-type JwksRefetch from \SineMacula\Laravel\Sso\Metadata\JwksRefetcher
 */
#[CoversClass(JwksRefetcher::class)]
final class JwksRefetcherTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The provider's issuer. */
    private const string ISSUER = FakeOpenIdProvider::ISSUER;

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T09:30:00+00:00';

    /** @var string When the default cooldown claimed at the start ends. */
    private const string COOLDOWN = '2026-11-01T09:35:00+00:00';

    /** @var string A token a concurrent refetch claimed with. */
    private const string OTHER_TOKEN = 'ffffffffffffffffffffffffffffffff';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's key, generated once. */
    private static ?FakeSigningKey $key = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's next key, generated once. */
    private static ?FakeSigningKey $next = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the refetch fetches through. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider refetched from. */
    private FakeOpenIdProvider $provider;

    /**
     * Bind a fixed clock and a fake fetcher serving the provider, and create
     * the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock    = new FixedClock(self::NOW);
        $this->fetcher  = new FakeFetcher;
        $this->provider = (new FakeOpenIdProvider(self::ISSUER, self::key()))->serve($this->fetcher);

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Fetcher::class, $this->fetcher);

        $this->usePackageTables();
    }

    /**
     * A refetch claims the cooldown before it fetches, fetches the URL it read
     * under its cap, replaces the keys exactly and clears its token, keeping
     * the cooldown; the fetch is stamped with the moment it validated.
     *
     * @return void
     */
    public function testARefetchReplacesTheKeysAndKeepsTheCooldown(): void
    {
        $connection = $this->connection(self::stored([self::key()]));

        $this->provider->publish(self::next());

        $clock  = $this->clock;
        $stored = self::stored([self::key(), self::next()]);

        $this->provider->respond('jwks', function (FetchRequest $request) use ($clock, $connection): FetchResult {
            unset($request);

            $claimed = $this->row($connection);

            self::assertSame(self::COOLDOWN, $claimed->jwks_refetch_at?->toIso8601String());
            self::assertSame(32, strlen((string) $claimed->jwks_claim_token));

            $clock->advance(5);

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });

        $answer = $this->refetch($connection);
        $row    = $this->row($connection);

        self::assertSame(self::answerOf('refreshed', null, FetchStatus::FETCHED, $stored), $answer);
        self::assertSame([$stored, 1, '2026-11-01T09:30:05+00:00', self::COOLDOWN, null, 0], [
            $row->jwks,
            $row->jwks_version,
            $row->jwks_fetched_at?->toIso8601String(),
            $row->jwks_refetch_at?->toIso8601String(),
            $row->jwks_claim_token,
            $row->trust_version,
        ]);

        $requests = array_map(static fn (FetchRequest $request): array => [$request->purpose->value, $request->url, $request->maxBytes], $this->fetcher->requests());

        self::assertSame([['jwks', self::ISSUER . '/jwks', 65536]], $requests);
    }

    /**
     * The cooldown is the configured one.
     *
     * @return void
     */
    public function testTheCooldownIsTheConfiguredOne(): void
    {
        config()->set('sso.oidc.jwks_refetch_cooldown_seconds', 60);

        $connection = $this->connection(null);

        $this->refetch($connection);

        self::assertSame('2026-11-01T09:31:00+00:00', $this->row($connection)->jwks_refetch_at?->toIso8601String());
    }

    /**
     * A hundred unknown `kid`s within the cooldown make exactly one fetch.
     *
     * @return void
     */
    public function testAHundredUnknownKidsMakeOneFetch(): void
    {
        $connection = $this->connection(self::stored([self::key()]));
        $keys       = app(ProviderKeys::class);

        foreach (range(1, 100) as $number) {
            self::assertSame(KeySelectionOutcome::UNKNOWN, $keys->select($connection, self::token('unknown-' . $number), self::rs256(), Clients::browser())->outcome);
        }

        self::assertCount(1, $this->fetcher->requests());
        self::assertSame(1, $this->row($connection)->jwks_version);
    }

    /**
     * Rows of `[seconds after the first refetch, fetches in all]`: the cooldown
     * boundary, to the second.
     *
     * @return iterable<string, array{0: int, 1: int}>
     */
    public static function provideCooldownBoundaries(): iterable
    {
        yield from [
            'a second under it' => [299, 1],
            'exactly at it'     => [300, 2],
            'a second over it'  => [301, 2],
        ];
    }

    /**
     * One more refetch is possible once the cooldown's boundary passes, exactly
     * at it included; and a success keeps it for just as long as a failure
     * does.
     *
     * @param  int  $seconds
     * @param  int  $fetches
     * @return void
     */
    #[DataProvider('provideCooldownBoundaries')]
    public function testOneMoreRefetchIsPossibleAtTheBoundary(int $seconds, int $fetches): void
    {
        foreach ([FakeTokenEndpoint::json(200, $this->provider->jwks()), FetchResult::failed()] as $response) {

            $fetcher = new FakeFetcher;

            $fetcher->respond(self::ISSUER . '/jwks', $response);

            $this->app?->instance(Fetcher::class, $fetcher);

            $connection = $this->connection(self::stored([self::key()]));
            $keys       = app(ProviderKeys::class);

            $keys->select($connection, self::token('unknown-1'), self::rs256(), Clients::browser());

            $this->clock->advance($seconds);

            $keys->select($connection, self::token('unknown-2'), self::rs256(), Clients::browser());

            self::assertCount($fetches, $fetcher->requests());

            $this->clock->advance(-$seconds);
        }
    }

    /**
     * Rows of `[response, reason, status]`: how a refetch fails.
     *
     * @return iterable<string, array{
     *     0: \SineMacula\Laravel\Sso\Fetching\FetchResult,
     *     1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason,
     *     2: \SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus
     * }>
     */
    public static function provideFailures(): iterable
    {
        yield from [
            'a fetch refused'     => [FetchResult::refused(), FailureReason::FETCH_REFUSED, FetchStatus::REFUSED],
            'a fetch failed'      => [FetchResult::failed(), FailureReason::FETCH_FAILED, FetchStatus::FAILED],
            'a server error'      => [FetchResult::fetched(500, [], '{}'), FailureReason::FETCH_FAILED, FetchStatus::FETCHED],
            'a redirect answered' => [FetchResult::fetched(302, [], ''), FailureReason::FETCH_FAILED, FetchStatus::FETCHED],
            'over the cap'        => [FetchResult::fetched(200, [], str_repeat('x', 65537)), FailureReason::FETCH_FAILED, FetchStatus::FAILED],
            'not JSON'            => [FetchResult::fetched(200, [], '<html></html>'), FailureReason::JWKS_INVALID, FetchStatus::FETCHED],
            'no admissible key'   => [FetchResult::fetched(200, [], '{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}'), FailureReason::JWKS_INVALID, FetchStatus::FETCHED],
            'a list of no keys'   => [FetchResult::fetched(200, [], '{"keys":[]}'), FailureReason::JWKS_INVALID, FetchStatus::FETCHED],
            ...self::hostileBodies(),
        ];
    }

    /**
     * A failure consumes the cooldown, keeps the last good keys and clears the
     * token alone.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $response
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus  $status
     * @return void
     */
    #[DataProvider('provideFailures')]
    public function testAFailureConsumesTheCooldownAndKeepsTheKeys(FetchResult $response, FailureReason $reason, FetchStatus $status): void
    {
        $stored     = self::stored([self::key()]);
        $connection = $this->connection($stored);

        $this->provider->respond('jwks', $response);

        $answer = $this->refetch($connection);
        $row    = $this->row($connection);

        self::assertSame(self::answerOf('failed', $reason, $status, $stored), $answer);
        self::assertSame([$stored, 0, null, self::COOLDOWN, null, 0], [
            $row->jwks,
            $row->jwks_version,
            $row->jwks_fetched_at,
            $row->jwks_refetch_at?->toIso8601String(),
            $row->jwks_claim_token,
            $row->trust_version,
        ]);
        self::assertSame(self::answerOf('cooling_down', null, null, $stored), $this->refetch($connection));
        self::assertCount(1, $this->fetcher->requests());
    }

    /**
     * Rows of `[keys, refreshed]`: how many keys a refetched JWKS holds.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideKeyCounts(): iterable
    {
        yield from [
            '50 keys' => [50, true],
            '51 keys' => [51, false],
        ];
    }

    /**
     * A refetched JWKS of 50 keys is stored, and one of 51 refused.
     *
     * @param  int  $count
     * @param  bool  $refreshed
     * @return void
     */
    #[DataProvider('provideKeyCounts')]
    public function testTheKeyLimitHolds(int $count, bool $refreshed): void
    {
        $keys = [];

        foreach (range(1, $count) as $number) {
            $keys[] = self::key()->jwk(null, 'sig', ['kid' => 'key-' . $number]);
        }

        $this->provider->respond('jwks', FakeTokenEndpoint::json(200, ['keys' => $keys]));

        self::assertSame($refreshed ? 'refreshed' : 'failed', $this->refetch($this->connection(null))['outcome']);
    }

    /**
     * Rows of `[offset, outcome]`: a JWKS's length against its cap.
     *
     * @return iterable<string, array{0: int, 1: string}>
     */
    public static function provideCapOffsets(): iterable
    {
        yield from [
            'under the cap' => [-1, 'refreshed'],
            'at the cap'    => [0, 'refreshed'],
            'over the cap'  => [1, 'failed'],
        ];
    }

    /**
     * A JWKS is refetched at its cap and under it, and refused over it.
     *
     * @param  int  $offset
     * @param  string  $outcome
     * @return void
     */
    #[DataProvider('provideCapOffsets')]
    public function testTheSizeCapHolds(int $offset, string $outcome): void
    {
        $members = ['keys' => [self::key()->jwk()]];
        $empty   = (string) json_encode([...$members, 'pad' => ''], JSON_UNESCAPED_SLASHES);
        $body    = (string) json_encode([...$members, 'pad' => str_repeat('x', 65536 + $offset - strlen($empty))], JSON_UNESCAPED_SLASHES);

        $this->provider->respond('jwks', FetchResult::fetched(200, [], $body));

        self::assertSame($outcome, $this->refetch($this->connection(null))['outcome']);
    }

    /**
     * Keys added alone void nothing and leave the trust version as it was, so a
     * refetch never voids its own callback, though the first JWKS was stored.
     *
     * @return void
     */
    public function testAddedKeysVoidNothing(): void
    {
        foreach ([self::stored([self::key()]), null] as $stored) {

            $connection = $this->connection($stored);
            $request    = $this->makeAuthorizationRequest($connection);
            $code       = $this->makeHandoffCode($connection);

            $this->provider->unpublish('rsa-2')->publish(self::next());

            self::assertSame('refreshed', $this->refetch($connection)['outcome']);
            self::assertSame(0, $this->row($connection)->trust_version);
            self::assertNull($request->refresh()->voided_at);
            self::assertNull($code->refresh()->voided_at);
        }
    }

    /**
     * A key removed is replaced exactly, voiding a stored request and code and
     * raising the trust version once.
     *
     * @return void
     */
    public function testARemovedKeyVoids(): void
    {
        $connection = $this->connection(self::stored([self::key(), self::next()]));
        $request    = $this->makeAuthorizationRequest($connection);
        $code       = $this->makeHandoffCode($connection);

        self::assertSame(self::stored([self::key()]), $this->refetch($connection)['jwks']);

        $row = $this->row($connection);

        self::assertSame([self::stored([self::key()]), 1, 1], [$row->jwks, $row->jwks_version, $row->trust_version]);
        self::assertSame(self::NOW, $request->refresh()->voided_at?->toIso8601String());
        self::assertSame(self::NOW, $code->refresh()->voided_at?->toIso8601String());
    }

    /**
     * A key replaced under the same `kid` voids and raises the trust version
     * once, and the replacement alone stands.
     *
     * @return void
     */
    public function testAKeyReplacedUnderItsKidVoids(): void
    {
        $connection = $this->connection(self::stored([self::next()->withKid('rsa-1')]));
        $request    = $this->makeAuthorizationRequest($connection);

        self::assertSame('refreshed', $this->refetch($connection)['outcome']);

        $row = $this->row($connection);

        self::assertSame([self::stored([self::key()]), 1], [$row->jwks, $row->trust_version]);
        self::assertNotNull($request->refresh()->voided_at);
    }

    /**
     * Rows of `[columns, settings]`: what changes while a refetch fetches, each
     * a lost compare and set.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>}>
     */
    public static function provideLostRefetches(): iterable
    {
        yield from [
            'the JWKS version raised'  => [['jwks_version' => 3], []],
            'the trust version raised' => [['trust_version' => 3], []],
            'the token taken over'     => [['jwks_claim_token' => self::OTHER_TOKEN], []],
            'the token cleared'        => [['jwks_claim_token' => null], []],
            'the issuer changed'       => [[], ['issuer' => 'https://other.example.test']],
            'the JWKS URI changed'     => [[], ['jwks_uri' => 'https://other.example.test/jwks']],
        ];
    }

    /**
     * A refetch that lost to a change made while it fetched writes nothing, on
     * what it read or on a failure, and answers the winner's keys from the
     * locked row with no other fetch.
     *
     * @param  array<string, mixed>  $columns
     * @param  array<string, mixed>  $settings
     * @return void
     */
    #[DataProvider('provideLostRefetches')]
    public function testALostRefetchWritesNothing(array $columns, array $settings): void
    {
        $winner = self::stored([self::next()]);

        foreach ([FakeTokenEndpoint::json(200, $this->provider->jwks()), FetchResult::failed()] as $response) {

            $connection = $this->connection(self::stored([self::key()]));
            $change     = ['jwks' => $winner, ...$columns];

            $this->provider->respond('jwks', function (FetchRequest $request) use ($connection, $change, $settings, $response): FetchResult {
                unset($request);

                $row = $this->row($connection);

                $row->forceFill([...$change, 'settings' => [...$row->settings, ...$settings]])->save();

                return $response;
            });

            $requests = count($this->fetcher->requests());
            $answer   = $this->refetch($connection);
            $row      = $this->row($connection);

            self::assertSame(['conflict', FailureReason::METADATA_CONFLICT, $winner], [$answer['outcome'], $answer['reason'], $answer['jwks']]);
            self::assertSame($response->status, $answer['fetch_status']);
            self::assertSame([$winner, $columns['jwks_version'] ?? 0, $columns['trust_version'] ?? 0, null, self::COOLDOWN], [
                $row->jwks,
                $row->jwks_version,
                $row->trust_version,
                $row->jwks_fetched_at,
                $row->jwks_refetch_at?->toIso8601String(),
            ]);
            self::assertCount($requests + 1, $this->fetcher->requests());

            if (array_key_exists('jwks_claim_token', $columns)) {
                self::assertSame($columns['jwks_claim_token'], $row->jwks_claim_token);
            } else {
                self::assertIsString($row->jwks_claim_token);
            }
        }
    }

    /**
     * A connection deleted while the refetch fetched answers a conflict with no
     * keys, and nothing to report.
     *
     * @return void
     */
    public function testAConnectionDeletedWhileItFetchedIsAConflict(): void
    {
        $connection = $this->connection(self::stored([self::key()]));
        $read       = $this->row($connection);

        $this->provider->respond('jwks', function (FetchRequest $request) use ($connection): FetchResult {
            unset($request);

            Connection::query()->whereKey($connection->id)->delete();

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });

        self::assertSame(
            self::answerOf('conflict', FailureReason::METADATA_CONFLICT, FetchStatus::FETCHED, null, null),
            app(JwksRefetcher::class)->refetch($read, self::rs256(), Clients::browser()),
        );
    }

    /**
     * Rows of `[attributes]`: what lets no claim be taken.
     *
     * @return iterable<string, array{0: \Closure(self): array<string, mixed>}>
     */
    public static function provideHeldCooldowns(): iterable
    {
        yield from [
            'the cooldown a second off' => [static fn (self $test): array => ['jwks_refetch_at' => $test->clock->now()->addSecond()]],
            'the JWKS written since'    => [static fn (self $test): array => ['jwks_version' => 9, 'jwks' => '[]', 'jwks_refetch_at' => null]],
        ];
    }

    /**
     * A refetch of a connection as it was read, when the cooldown holds or the
     * JWKS was written since, claims nothing and fetches nothing, and answers
     * the keys stored now.
     *
     * @param  \Closure(self): array<string, mixed>  $attributes
     * @return void
     */
    #[DataProvider('provideHeldCooldowns')]
    public function testARefetchThatClaimsNothingFetchesNothing(\Closure $attributes): void
    {
        $connection = $this->connection(self::stored([self::key()]));
        $read       = $this->row($connection);
        $row        = $this->row($connection);

        $row->forceFill($attributes($this))->save();

        $answer = app(JwksRefetcher::class)->refetch($read, self::rs256(), Clients::browser());

        self::assertSame(self::answerOf('cooling_down', null, null, $this->row($connection)->jwks), $answer);
        self::assertNull($this->row($connection)->jwks_claim_token);

        $this->fetcher->assertNothingFetched();
    }

    /**
     * Rows of `[seconds the fetch took, stale limit, outcome]`: around the
     * stale limit counted from the moment the JWKS was validated.
     *
     * @return iterable<string, array{0: int, 1: int, 2: string}>
     */
    public static function provideCommits(): iterable
    {
        yield from [
            'a second before the limit' => [86399, 86400, 'refreshed'],
            'at the limit'              => [86400, 86400, 'failed'],
            'a second over the limit'   => [86401, 86400, 'failed'],
            'no limit, however long'    => [86401, 0, 'refreshed'],
        ];
    }

    /**
     * What was validated is checked against the stale limit at commit, as a
     * scheduled refresh checks it: past it, nothing is replaced, nothing is
     * reported as a success, and the cooldown stays spent.
     *
     * @param  int  $seconds
     * @param  int  $limit
     * @param  string  $outcome
     * @return void
     */
    #[DataProvider('provideCommits')]
    public function testTheStaleLimitIsCheckedAtCommit(int $seconds, int $limit, string $outcome): void
    {
        config()->set('sso.metadata.stale_limit_seconds', $limit);

        $connection = $this->connection(self::stored([self::key()]));

        $this->provider->publish(self::next());
        $this->slowingCommitBy($seconds);
        $this->startRecordingEvents();

        $answer = $this->refetch($connection);
        $row    = $this->row($connection);
        $events = $this->recordedEvents();

        self::assertSame($outcome, $answer['outcome']);
        self::assertCount(1, $events);

        if ($outcome === 'refreshed') {
            self::assertInstanceOf(JwksRefreshed::class, $events[0]);
            self::assertSame(1, $row->jwks_version);
            self::assertSame(self::stored([self::key(), self::next()]), $row->jwks);

            return;
        }

        self::assertInstanceOf(JwksRefreshFailed::class, $events[0]);
        self::assertSame(FailureReason::METADATA_EXPIRED, $events[0]->reason);
        self::assertSame(FailureReason::METADATA_EXPIRED, $answer['reason']);
        self::assertSame(FetchStatus::FETCHED, $answer['fetch_status']);
        self::assertSame(self::stored([self::key()]), $row->jwks);
        self::assertSame(0, $row->jwks_version);
        self::assertNull($row->jwks_fetched_at);
        self::assertNull($row->jwks_claim_token);
        self::assertNotNull($row->jwks_refetch_at);
    }

    /**
     * Rows of `[removes a key]`: a stale fetch, whether it only adds a key or
     * would remove one.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideStaleFetches(): iterable
    {
        yield 'adding a key' => [false];
        yield 'removing a key' => [true];
    }

    /**
     * A stale fetch replaces nothing, so one that would remove a key voids
     * nothing and raises no trust version either: exactly one failure is
     * reported, and no receipt is answered for the request that asked.
     *
     * @param  bool  $removes
     * @return void
     */
    #[DataProvider('provideStaleFetches')]
    public function testAStaleFetchVoidsNothing(bool $removes): void
    {
        config()->set('sso.metadata.stale_limit_seconds', 86400);

        $connection = $this->connection(self::stored($removes ? [self::key(), self::next()] : [self::key()]));
        $trigger    = $this->makeAuthorizationRequest($connection, ['consumed_at' => $this->clock->now()]);
        $other      = $this->makeAuthorizationRequest($connection);

        if ($removes) {
            $this->provider->unpublish('rsa-2');
        } else {
            $this->provider->publish(self::next());
        }

        $this->slowingCommitBy(86400);
        $this->startRecordingEvents();

        $answer = $this->refetchFor($connection, $trigger->reference);
        $events = $this->recordedEvents();

        self::assertSame(['failed', FailureReason::METADATA_EXPIRED, null, 0], [$answer['outcome'], $answer['reason'], $answer['receipt'], $answer['trust_version']]);
        self::assertSame(0, $this->row($connection)->trust_version);
        self::assertNull($trigger->fresh()?->voided_at);
        self::assertNull($other->fresh()?->voided_at);
        self::assertCount(1, $events);
        self::assertInstanceOf(JwksRefreshFailed::class, $events[0]);
    }

    /**
     * A committed refetch resets the JWKS's freshness alone, never the
     * discovery document's.
     *
     * @return void
     */
    public function testARefetchResetsTheJwksFreshnessAlone(): void
    {
        $fetched    = $this->clock->now()->subDays(10);
        $connection = $this->makeConnection([
            'jwks'                => self::stored([self::key()]),
            'jwks_fetched_at'     => $fetched,
            'metadata_fetched_at' => $fetched,
            'settings'            => ['issuer' => self::ISSUER, 'jwks_uri' => self::ISSUER . '/jwks'],
        ]);

        $this->provider->publish(self::next());

        self::assertSame('refreshed', $this->refetch($connection)['outcome']);

        $row = $this->row($connection);

        self::assertSame($this->clock->now()->toIso8601String(), $row->jwks_fetched_at?->toIso8601String());
        self::assertSame($fetched->toIso8601String(), $row->metadata_fetched_at?->toIso8601String());
    }

    /**
     * Each token the cooldown turns away is counted up to the cap, after which
     * the row is not written at all; the next claim answers the count and
     * clears it.
     *
     * @return void
     */
    public function testACooldownCountsWhatItTurnsAwayUpToTheCap(): void
    {
        $connection = $this->connection(self::stored([self::key()]));

        $this->refetch($connection);

        foreach ([1, 2, 3] as $count) {
            self::assertSame(0, $this->refetch($connection)['suppressed']);
            self::assertSame($count, $this->row($connection)->jwks_refetch_suppressed);
        }

        Connection::query()->whereKey($connection->id)->update(['jwks_refetch_suppressed' => JwksRefetcher::MAX_COUNTED_SUPPRESSED]);

        $writes = 0;

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use (&$writes): void {
            $writes += (int) (str_contains($query->sql, 'jwks_refetch_suppressed') && str_starts_with($query->sql, 'update'));
        });

        $this->refetch($connection);

        self::assertSame(JwksRefetcher::MAX_COUNTED_SUPPRESSED, $this->row($connection)->jwks_refetch_suppressed);

        // The failed claim names the column in its SET, once; the count does
        // not
        self::assertSame(1, $writes);

        $this->clock->advance(300);

        self::assertSame(100, $this->refetch($connection)['suppressed']);
        self::assertSame(0, $this->row($connection)->jwks_refetch_suppressed);
    }

    /**
     * A key removed, asked for by a consumed request, spares that request alone
     * and answers its receipt: the transition it made, exactly. Nothing else is
     * spared.
     *
     * @return void
     */
    public function testARemovedKeySparesTheRequestThatAsked(): void
    {
        $connection = $this->connection(self::stored([self::key(), self::next()]));
        $trigger    = $this->makeAuthorizationRequest($connection, ['consumed_at' => $this->clock->now()]);
        $other      = $this->makeAuthorizationRequest($connection, ['consumed_at' => $this->clock->now()]);
        $code       = $this->makeHandoffCode($connection);

        $this->provider->unpublish('rsa-2');

        $answer  = $this->refetchFor($connection, $trigger->reference);
        $receipt = $answer['receipt'];

        self::assertInstanceOf(TransitionReceipt::class, $receipt);
        self::assertSame(
            [$connection->id, $trigger->id, 0, 1, 1],
            [$receipt->connectionId, $receipt->requestId, $receipt->fromTrustVersion, $receipt->toTrustVersion, $receipt->jwksVersion],
        );
        self::assertNull($receipt->keyThumbprint());
        self::assertNull($receipt->algorithm);
        self::assertSame(1, $answer['trust_version']);
        self::assertNull($trigger->fresh()?->voided_at);
        self::assertNotNull($other->fresh()?->voided_at);
        self::assertNotNull($code->fresh()?->voided_at);
    }

    /**
     * Rows of `[attributes, reference known, voided at after the rotation]`: a
     * request no rotation spares, and what becomes of it.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool, 2: ?string}>
     */
    public static function provideUnsparedRequests(): iterable
    {
        $earlier = '2026-11-01T09:00:00+00:00';

        yield from [
            'not consumed'          => [['consumed_at' => null], true, self::NOW],
            'finished'              => [['completed_at' => CarbonImmutable::parse($earlier)], true, null],
            'already voided'        => [['voided_at' => CarbonImmutable::parse($earlier)], true, $earlier],
            'of another trust'      => [['trust_version' => 7], true, self::NOW],
            'of another connection' => [[], false, null],
        ];
    }

    /**
     * A request that is not exactly the consumed, unfinished, unvoided request
     * of the locked trust version is never spared, so what voided it stands,
     * its first moment kept; it gets no receipt, and the rotation voids what it
     * would, leaving a finished request and another connection's untouched.
     *
     * @param  array<string, mixed>  $attributes
     * @param  bool  $own
     * @param  ?string  $voidedAt
     * @return void
     */
    #[DataProvider('provideUnsparedRequests')]
    public function testARequestThatIsNotOpenIsNeverSpared(array $attributes, bool $own, ?string $voidedAt): void
    {
        $connection = $this->connection(self::stored([self::key(), self::next()]));
        $owner      = $own ? $connection : $this->connection(null);
        $request    = $this->makeAuthorizationRequest($owner, ['consumed_at' => $this->clock->now(), ...$attributes]);

        $this->provider->unpublish('rsa-2');

        $answer = $this->refetchFor($connection, $request->reference);

        self::assertNull($answer['receipt']);
        self::assertSame(1, $answer['trust_version']);
        self::assertSame($voidedAt, $request->fresh()?->voided_at?->toIso8601String());
    }

    /**
     * A key only added answers no receipt, whoever asked, and voids nothing.
     *
     * @return void
     */
    public function testAnAddedKeyAnswersNoReceipt(): void
    {
        $connection = $this->connection(self::stored([self::key()]));
        $request    = $this->makeAuthorizationRequest($connection, ['consumed_at' => $this->clock->now()]);

        $this->provider->publish(self::next());

        $answer = $this->refetchFor($connection, $request->reference);

        self::assertNull($answer['receipt']);
        self::assertSame(0, $answer['trust_version']);
        self::assertNull($request->fresh()?->voided_at);
    }

    /**
     * A failed fetch answers no receipt, voids nothing and spends the cooldown.
     *
     * @return void
     */
    public function testAFailedFetchAnswersNoReceipt(): void
    {
        $connection = $this->connection(self::stored([self::key()]));
        $request    = $this->makeAuthorizationRequest($connection, ['consumed_at' => $this->clock->now()]);

        $this->provider->respond('jwks', FetchResult::failed());

        $answer = $this->refetchFor($connection, $request->reference);

        self::assertSame('failed', $answer['outcome']);
        self::assertNull($answer['receipt']);
        self::assertNull($request->fresh()?->voided_at);
    }

    /**
     * A refetch inside a transaction is the caller's mistake: it fetches before
     * it writes.
     *
     * @return void
     */
    public function testARefetchNeverRunsInsideATransaction(): void
    {
        $connection = $this->connection(self::stored([self::key()]));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A JWKS refetch runs outside any transaction on the storage connection, since it fetches before it writes.');

        DB::transaction(fn (): array => $this->refetch($connection));
    }

    /**
     * A refetch that replaced the keys reports what it added and removed.
     *
     * @return void
     */
    public function testARefetchReportsWhatItChanged(): void
    {
        $connection = $this->connection(self::stored([self::key()]));

        $this->provider->publish(self::next());
        $this->startRecordingEvents();

        $this->refetch($connection);

        $events = $this->recordedEvents();

        self::assertCount(1, $events);
        self::assertInstanceOf(JwksRefreshed::class, $events[0]);
        self::assertSame([1, 1, 0, false], [$events[0]->jwksVersion, $events[0]->keysAdded, $events[0]->keysRemoved, $events[0]->trustChanged]);
    }

    /**
     * A refetch that failed reports why, and when the next may run.
     *
     * @return void
     */
    public function testARefetchReportsItsFailure(): void
    {
        $connection = $this->connection(self::stored([self::key()]));

        $this->provider->respond('jwks', FetchResult::failed());
        $this->startRecordingEvents();

        $this->refetch($connection);

        $events = $this->recordedEvents();

        self::assertCount(1, $events);
        self::assertInstanceOf(JwksRefreshFailed::class, $events[0]);
        self::assertSame([FailureReason::FETCH_FAILED, self::COOLDOWN], [$events[0]->reason, $events[0]->nextRefetchAt?->toIso8601String()]);
    }

    /**
     * A refetch that lost to a change made while it fetched reports the
     * conflict, once.
     *
     * @return void
     */
    public function testARefetchReportsItsConflict(): void
    {
        $connection = $this->connection(self::stored([self::key()]));

        $this->provider->respond('jwks', function (FetchRequest $request) use ($connection): FetchResult {
            unset($request);

            Connection::query()->whereKey($connection->id)->update(['jwks_version' => 7]);

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });
        $this->startRecordingEvents();

        $this->refetch($connection);

        $events = $this->recordedEvents();

        self::assertCount(1, $events);
        self::assertInstanceOf(JwksRefreshFailed::class, $events[0]);
        self::assertSame([FailureReason::METADATA_CONFLICT, self::COOLDOWN], [$events[0]->reason, $events[0]->nextRefetchAt?->toIso8601String()]);
    }

    /**
     * A connection gone before its refetch claims anything has no keys to
     * answer.
     *
     * @return void
     */
    public function testAConnectionGoneBeforeItsClaimHasNoKeys(): void
    {
        $connection = $this->connection(self::stored([self::key()]));
        $read       = $this->row($connection);

        Connection::query()->whereKey($connection->id)->delete();

        self::assertSame(
            self::answerOf('cooling_down', null, null, null, null),
            app(JwksRefetcher::class)->refetch($read, self::rs256(), Clients::browser()),
        );
    }

    /**
     * A JWKS the refetch must refuse whole, however it could be read.
     *
     * @return array<string, array{
     *     0: \SineMacula\Laravel\Sso\Fetching\FetchResult,
     *     1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason,
     *     2: \SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus
     * }>
     */
    private static function hostileBodies(): array
    {
        $jwk  = (string) json_encode(self::next()->jwk());
        $rows = [
            'a duplicate admissible kid' => '{"keys":[' . $jwk . ',' . $jwk . ']}',
            'a repeated member'          => '{"keys":[],"keys":[' . $jwk . ']}',
            'an escaped nested member'   => '{"keys":[{"' . chr(92) . 'u006bty":"oct",' . substr($jwk, 1) . ']}',
            'keys an object of a list'   => '{"keys":{"0":' . $jwk . '}}',
            'an entry an empty list'     => '{"keys":[[],' . $jwk . ']}',
            'key_ops an object'          => '{"keys":[' . substr($jwk, 0, -1) . ',"key_ops":{"0":"verify"}}]}',
        ];

        return array_map(static fn (string $body): array => [FetchResult::fetched(200, [], $body), FailureReason::JWKS_INVALID, FetchStatus::FETCHED], $rows);
    }

    /**
     * What a refetch answers.
     *
     * @param  string  $outcome
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus  $status
     * @param  ?string  $jwks
     * @param  ?int  $trustVersion
     * @return array<string, mixed>
     */
    private static function answerOf(string $outcome, ?FailureReason $reason, ?FetchStatus $status, ?string $jwks, ?int $trustVersion = 0): array
    {
        return ['outcome' => $outcome, 'reason' => $reason, 'fetch_status' => $status, 'jwks' => $jwks, 'trust_version' => $trustVersion, 'suppressed' => 0, 'receipt' => null];
    }

    /**
     * Bind a clock that moves on by the seconds given once the claim and the
     * validated moment have each read it, so only the commit sees the time
     * passed.
     *
     * @param  int  $seconds
     * @return void
     */
    private function slowingCommitBy(int $seconds): void
    {
        $clock = $this->clock;

        $this->app?->instance(Clock::class, new class ($clock, $seconds) implements Clock {
            /** @var int How many times the clock has been read. */
            private int $reads = 0;

            /**
             * Constructor.
             *
             * @param  \Tests\Fixtures\FixedClock  $clock
             * @param  int  $seconds
             */
            public function __construct(

                /** The clock read. */
                private readonly FixedClock $clock,

                /** How long the commit takes. */
                private readonly int $seconds,
            ) {}

            /**
             * The clock's now, moved on once the claim and the validated moment
             * have each read it, so only the commit sees the time passed.
             *
             * @return \Carbon\CarbonImmutable
             */
            #[\Override]
            public function now(): CarbonImmutable
            {
                $now = $this->clock->now();

                if (++$this->reads === 2) {
                    $this->clock->advance($this->seconds);
                }

                return $now;
            }
        });
    }

    /**
     * A refetch of the connection as stored, asked for by the request named.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $reference
     * @return JwksRefetch
     *
     * @throws \Throwable
     */
    private function refetchFor(Connection $connection, string $reference): array
    {
        return app(JwksRefetcher::class)->refetch($this->row($connection), self::rs256(), Clients::browser(), RequestReference::fromString($reference));
    }

    /**
     * Refetch the connection as stored now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return JwksRefetch
     */
    private function refetch(Connection $connection): array
    {
        return app(JwksRefetcher::class)->refetch($this->row($connection), self::rs256(), Clients::browser());
    }

    /**
     * An OIDC connection pointing at the provider, storing the keys given.
     *
     * @param  ?string  $jwks
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connection(?string $jwks): Connection
    {
        return $this->makeConnection(['jwks' => $jwks, 'settings' => ['issuer' => self::ISSUER, 'jwks_uri' => self::ISSUER . '/jwks']]);
    }

    /**
     * The connection as stored now, read on the write connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function row(Connection $connection): Connection
    {
        return Connection::query()->useWritePdo()->findOrFail($connection->id);
    }

    /**
     * The keys as a connection stores them.
     *
     * @param  list<\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey>  $keys
     * @return string
     */
    private static function stored(array $keys): string
    {
        $jwks = (string) json_encode(['keys' => array_map(static fn (FakeSigningKey $key): array => $key->jwk(), $keys)]);

        return ProviderKeySet::read($jwks, self::rs256(), 65536, 50)?->toStored() ?? '';
    }

    /**
     * The RS256 allow-list.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList
     */
    private static function rs256(): AlgorithmAllowList
    {
        return AlgorithmAllowList::of(['RS256']);
    }

    /**
     * A token signed by the provider's key under the `kid`.
     *
     * @param  string  $kid
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken
     *
     * @throws \LogicException
     */
    private static function token(string $kid): CompactToken
    {
        return CompactToken::parse(JwsSigner::sign(['alg' => 'RS256', 'kid' => $kid], ['sub' => 'a'], self::key()), 16384) ?? throw new \LogicException('The token was refused.');
    }

    /**
     * The provider's key, generated once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(): FakeSigningKey
    {
        return self::$key ??= FakeSigningKey::rsa();
    }

    /**
     * The provider's next key, generated once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function next(): FakeSigningKey
    {
        return self::$next ??= FakeSigningKey::rsa('rsa-2');
    }
}
