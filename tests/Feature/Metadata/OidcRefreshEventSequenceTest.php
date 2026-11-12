<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\JwksRefreshed;
use SineMacula\Laravel\Sso\Events\JwksRefreshFailed;
use SineMacula\Laravel\Sso\Events\MetadataRefreshed;
use SineMacula\Laravel\Sso\Events\MetadataRefreshFailed;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Metadata\DiscoveryImporter;
use SineMacula\Laravel\Sso\Metadata\JwksRefetcher;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\OidcMetadataSource;
use SineMacula\Laravel\Sso\Metadata\ProviderKeys;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use SineMacula\Laravel\Sso\Testing\Oidc\JwsSigner;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Pins the events of an OIDC import, refresh and refetch, with their full
 * context.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DiscoveryImporter::class)]
#[CoversClass(OidcMetadataSource::class)]
#[CoversClass(JwksRefetcher::class)]
#[CoversClass(ProviderKeys::class)]
final class OidcRefreshEventSequenceTest extends TestCase
{
    use CapturesLogs, RecordsEventSequences, UsesConnections;

    /** @var string The tenant whose connection refreshes. */
    private const string TENANT = 'tenant-1';

    /** @var string The issuer the connection is pinned to. */
    private const string ISSUER = FakeOpenIdProvider::ISSUER;

    /** @var string A URL the provider's document may move a setting to. */
    private const string MOVED = 'https://moved.example.test/token';

    /** @var string When a failure now is next tried, and when a refetch's cooldown now ends. */
    private const string IN_FIVE_MINUTES = '2026-11-01T09:35:00+00:00';

    /** @var string When the winner of a race left the next attempt. */
    private const string WINNERS_NEXT = '2026-11-01T11:00:00+00:00';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's key, generated once. */
    private static ?FakeSigningKey $key = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's next key, generated once. */
    private static ?FakeSigningKey $next = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher everything fetches through. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider. */
    private FakeOpenIdProvider $provider;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection refreshed. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Identities\Caller The administrator who asks. */
    private Caller $actor;

    /**
     * Bind a fixed clock, a fetcher serving the provider and a request, enable
     * OIDC and refresh, create a refreshing connection, and record events and
     * logs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher  = new FakeFetcher;
        $this->provider = (new FakeOpenIdProvider(self::ISSUER, self::key()))->serve($this->fetcher);
        $this->actor    = new Caller(new IdentityReference('App\Models\User', '42'));

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Fetcher::class, $this->fetcher);

        config()->set('sso.features.oidc', true);
        config()->set('sso.features.metadata_refresh', true);

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'jwks'     => self::stored([self::key()]),
            'settings' => OidcSettings::fromArray([
                'issuer'                 => self::ISSUER,
                'authorization_endpoint' => self::ISSUER . '/authorize',
                'token_endpoint'         => self::ISSUER . '/token',
                'jwks_uri'               => self::ISSUER . '/jwks',
                'userinfo_endpoint'      => self::ISSUER . '/userinfo',
                'returns_iss'            => true,
                'client_id'              => FakeOpenIdProvider::CLIENT_ID,
                'metadata_refresh'       => true,
            ])->toArray(),
        ]);

        $this->captureLogs();
        $this->startRecordingEvents();
    }

    /**
     * An import reports nothing, named connection or not.
     *
     * @return void
     */
    public function testAnImportReportsNothing(): void
    {
        self::assertTrue(app(DiscoveryImporter::class)->import(self::TENANT, self::ISSUER)->isProposed());
        self::assertTrue(app(DiscoveryImporter::class)->import(self::TENANT, self::ISSUER, $this->connection->id)->isProposed());

        $this->assertNoEvents();
    }

    /**
     * A scheduled refresh adding keys reports the refresh alone, with no actor
     * or trust change.
     *
     * @return void
     */
    public function testARefreshAddingKeysReportsTheRefresh(): void
    {
        $this->provider->publish(self::next());

        $this->refresher()->refreshDue(Clients::browser());

        $this->assertEventSequence([MetadataRefreshed::class]);

        $refreshed = $this->recordedEvents()[0];

        self::assertInstanceOf(MetadataRefreshed::class, $refreshed);
        self::assertSame([['jwks'], 1, false], [$refreshed->changedSettings, $refreshed->metadataVersion, $refreshed->trustChanged]);
        self::assertSame($this->context(null), $refreshed->context()->toArray());
    }

    /**
     * An administrator's refresh moving an endpoint and removing a key reports
     * the update then the refresh.
     *
     * @return void
     */
    public function testARefreshMovingAnEndpointAndRemovingAKeyReportsBoth(): void
    {
        Connection::query()->whereKey($this->connection->id)->update(['jwks' => self::stored([self::key(), self::next()])]);

        $this->provider->withDiscovery(['token_endpoint' => self::MOVED]);

        $this->refresher()->refreshNow(self::TENANT, $this->connection->id, $this->actor, Clients::browser());

        $this->assertEventSequence([ConnectionUpdated::class, MetadataRefreshed::class]);

        [$updated, $refreshed] = $this->recordedEvents();

        self::assertInstanceOf(ConnectionUpdated::class, $updated);
        self::assertInstanceOf(MetadataRefreshed::class, $refreshed);
        self::assertSame(['token_endpoint'], $updated->changedSettings);
        self::assertSame([['token_endpoint', 'jwks'], 1, true], [$refreshed->changedSettings, $refreshed->metadataVersion, $refreshed->trustChanged]);
        self::assertSame($this->context('42'), $updated->context()->toArray());
        self::assertSame($this->context('42'), $refreshed->context()->toArray());
    }

    /**
     * A failed refresh reports one failure with its reason, failure count and
     * next attempt.
     *
     * @return void
     */
    public function testARefreshFailureReportsOneFailure(): void
    {
        Connection::query()->whereKey($this->connection->id)->update(['metadata_fetched_at' => '2026-10-31 09:30:00']);

        $this->provider->respond('discovery', FetchResult::failed());

        $this->refresher()->refreshDue(Clients::browser());

        $this->assertEventSequence([MetadataRefreshFailed::class]);

        $failed = $this->recordedEvents()[0];

        self::assertInstanceOf(MetadataRefreshFailed::class, $failed);
        self::assertSame([FailureReason::FETCH_FAILED, 1, self::IN_FIVE_MINUTES], [$failed->reason, $failed->failures, $failed->nextAttemptAt?->toIso8601String()]);
        self::assertSame($this->context(null), $failed->context()->toArray());
    }

    /**
     * A refresh that lost reports one conflict with the winner's failure count
     * and next attempt.
     *
     * @return void
     */
    public function testAConflictReportsTheWinnersFailuresAndNextAttempt(): void
    {
        $this->provider->withDiscovery(['token_endpoint' => self::MOVED]);
        $this->provider->respond('jwks', function (FetchRequest $request): FetchResult {
            unset($request);

            Connection::query()->whereKey($this->connection->id)->update([
                'trust_version'             => 1,
                'metadata_refresh_failures' => 3,
                'metadata_refresh_at'       => '2026-11-01 11:00:00',
            ]);

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });

        $this->refresher()->refreshNow(self::TENANT, $this->connection->id, $this->actor, Clients::browser());

        $this->assertEventSequence([MetadataRefreshFailed::class]);

        $failed = $this->recordedEvents()[0];

        self::assertInstanceOf(MetadataRefreshFailed::class, $failed);
        self::assertSame([FailureReason::METADATA_CONFLICT, 3, self::WINNERS_NEXT], [$failed->reason, $failed->failures, $failed->nextAttemptAt?->toIso8601String()]);
        self::assertSame($this->context('42'), $failed->context()->toArray());
    }

    /**
     * A refetch adding a key reports it refreshed, with its version and
     * additions.
     *
     * @return void
     */
    public function testARefetchAddingAKeyReportsItRefreshed(): void
    {
        $this->provider->publish(self::next());

        app(ProviderKeys::class)->select($this->connection, self::token('rsa-2'), self::rs256(), Clients::browser());

        $this->assertEventSequence([JwksRefreshed::class]);

        $refreshed = $this->recordedEvents()[0];

        self::assertInstanceOf(JwksRefreshed::class, $refreshed);
        self::assertSame([1, 1, 0, false], [$refreshed->jwksVersion, $refreshed->keysAdded, $refreshed->keysRemoved, $refreshed->trustChanged]);
        self::assertSame($this->context(null), $refreshed->context()->toArray());
    }

    /**
     * A refetch removing a key reports what it removed and the trust changed.
     *
     * @return void
     */
    public function testARefetchRemovingAKeyReportsTheTrustChanged(): void
    {
        Connection::query()->whereKey($this->connection->id)->update(['jwks' => self::stored([self::key(), self::next()])]);

        app(ProviderKeys::class)->select($this->connection, self::token('rsa-3'), self::rs256(), Clients::browser());

        $this->assertEventSequence([JwksRefreshed::class]);

        $refreshed = $this->recordedEvents()[0];

        self::assertInstanceOf(JwksRefreshed::class, $refreshed);
        self::assertSame([1, 0, 1, true], [$refreshed->jwksVersion, $refreshed->keysAdded, $refreshed->keysRemoved, $refreshed->trustChanged]);
    }

    /**
     * A refetch that failed reports one failure, with when the next may start.
     *
     * @return void
     */
    public function testARefetchFailureReportsOneFailure(): void
    {
        $this->provider->respond('jwks', FetchResult::failed());

        app(ProviderKeys::class)->select($this->connection, self::token('rsa-2'), self::rs256(), Clients::browser());

        $this->assertEventSequence([JwksRefreshFailed::class]);

        $failed = $this->recordedEvents()[0];

        self::assertInstanceOf(JwksRefreshFailed::class, $failed);
        self::assertSame([FailureReason::FETCH_FAILED, self::IN_FIVE_MINUTES], [$failed->reason, $failed->nextRefetchAt?->toIso8601String()]);
        self::assertSame($this->context(null), $failed->context()->toArray());
    }

    /**
     * A refetch that lost reports one conflict with the winner's next start.
     *
     * @return void
     */
    public function testALostRefetchReportsAConflict(): void
    {
        $this->provider->respond('jwks', function (FetchRequest $request): FetchResult {
            unset($request);

            Connection::query()->whereKey($this->connection->id)->update(['jwks_version' => 5, 'jwks_refetch_at' => '2026-11-01 11:00:00']);

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });

        app(ProviderKeys::class)->select($this->connection, self::token('rsa-2'), self::rs256(), Clients::browser());

        $this->assertEventSequence([JwksRefreshFailed::class]);

        $failed = $this->recordedEvents()[0];

        self::assertInstanceOf(JwksRefreshFailed::class, $failed);
        self::assertSame([FailureReason::METADATA_CONFLICT, self::WINNERS_NEXT], [$failed->reason, $failed->nextRefetchAt?->toIso8601String()]);
    }

    /**
     * A refetch the cooldown holds, and a selection that needs none, report
     * nothing.
     *
     * @return void
     */
    public function testARefetchThatDidNotRunReportsNothing(): void
    {
        $keys = app(ProviderKeys::class);

        $keys->select($this->connection, self::token('rsa-1'), self::rs256(), Clients::browser());

        Connection::query()->whereKey($this->connection->id)->update(['jwks_refetch_at' => '2026-11-01 11:00:00']);

        $keys->select($this->connection, self::token('rsa-2'), self::rs256(), Clients::browser());

        $this->assertNoEvents();
    }

    /**
     * Every event is dispatched once its transaction has committed.
     *
     * @return void
     */
    public function testEveryEventIsDispatchedAfterCommit(): void
    {
        /** @var \ArrayObject<int, int> $levels */
        $levels = new \ArrayObject;

        Event::listen(SsoEvent::class, static function () use ($levels): void {
            $levels->append(DB::connection(StorageConnection::name())->transactionLevel());
        });

        Connection::query()->whereKey($this->connection->id)->update(['jwks' => self::stored([self::key(), self::next()])]);

        $this->provider->withDiscovery(['token_endpoint' => self::MOVED]);

        $this->refresher()->refreshNow(self::TENANT, $this->connection->id, $this->actor, Clients::browser());

        Connection::query()->whereKey($this->connection->id)->update(['jwks' => self::stored([self::key(), self::next()]), 'jwks_refetch_at' => null]);

        app(ProviderKeys::class)->select($this->connection, self::token('rsa-3'), self::rs256(), Clients::browser());

        Connection::query()->whereKey($this->connection->id)->update(['jwks_refetch_at' => null]);

        $this->provider->respond('jwks', FetchResult::failed());

        app(ProviderKeys::class)->select($this->connection, self::token('rsa-3'), self::rs256(), Clients::browser());

        $this->assertEventSequence([ConnectionUpdated::class, MetadataRefreshed::class, JwksRefreshed::class, JwksRefreshFailed::class]);

        self::assertSame([0, 0, 0, 0], $levels->getArrayCopy());
    }

    /**
     * A refresh inside an outer transaction reports only once that transaction
     * commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoRefreshEventEscapesARollback(): void
    {
        $source = app(OidcMetadataSource::class);
        $before = $this->row();
        $claim  = $source->claim($before);

        self::assertNotNull($claim);

        $fetched = $source->fetch($claim);

        try {
            DB::connection(StorageConnection::name())->transaction(function () use ($source, $claim, $fetched): void {
                self::assertTrue($source->write($claim, $fetched, null, Clients::browser())->isRefreshed());

                throw new \RuntimeException('Rolled back.');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('Rolled back.', $exception->getMessage());
        }

        self::assertSame(0, $this->row()->metadata_version);

        $this->assertNoEvents();
    }

    /**
     * A refetch that fails in its write rolls back, and no event escapes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoRefetchEventEscapesARollback(): void
    {
        Connection::query()->whereKey($this->connection->id)->update(['jwks' => self::stored([self::key(), self::next()])]);

        $this->app?->instance(InFlightVoider::class, new readonly class (app(Clock::class)) extends InFlightVoider {
            /**
             * Void, then fail.
             *
             * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
             * @param  ?string  $spared
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function voidFor(Connection $locked, ?string $spared = null): void
            {
                parent::voidFor($locked, $spared);

                throw new \RuntimeException('Rolled back.');
            }
        });

        try {
            app(ProviderKeys::class)->select($this->connection, self::token('rsa-3'), self::rs256(), Clients::browser());

            self::fail('The write did not fail.');
        } catch (\RuntimeException $exception) {
            self::assertSame('Rolled back.', $exception->getMessage());
        }

        $row = $this->row();

        self::assertSame([0, 0, self::stored([self::key(), self::next()])], [$row->jwks_version, $row->trust_version, $row->jwks]);

        $this->assertNoEvents();
    }

    /**
     * No event, log or result holds a key, URL, body or token, claim tokens
     * included.
     *
     * @return void
     */
    public function testNothingReportedHoldsAKeyAUrlABodyOrAToken(): void
    {
        $token   = self::token('rsa-2');
        $moduli  = [self::modulusOf(self::next()), self::modulusOf(self::key())];
        $needles = ['op.example.test', 'moved.example.test', 'provider-detail', ...$moduli, $token->compact()];
        $results = [];
        $seen    = new \ArrayObject;

        $this->provider->publish(self::next())->withDiscovery(['token_endpoint' => self::MOVED]);

        $this->provider->respond('jwks', function (FetchRequest $request) use ($seen): FetchResult {
            unset($request);

            $row = $this->row();

            $seen->append((string) ($row->metadata_claim_token ?? $row->jwks_claim_token));

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });

        $results[] = $this->refresher()->refreshNow(self::TENANT, $this->connection->id, $this->actor, Clients::browser());

        Connection::query()->whereKey($this->connection->id)->update(['jwks' => self::stored([self::key()]), 'jwks_refetch_at' => null]);

        app(ProviderKeys::class)->select($this->connection, $token, self::rs256(), Clients::browser());

        $this->provider->respond('discovery', FetchResult::fetched(500, [], 'provider-detail'));

        $results[] = $this->refresher()->refreshNow(self::TENANT, $this->connection->id, $this->actor, Clients::browser());

        Connection::query()->whereKey($this->connection->id)->update(['jwks' => self::stored([self::key()]), 'jwks_refetch_at' => null]);

        $this->provider->respond('jwks', FetchResult::fetched(500, [], 'provider-detail'));

        app(ProviderKeys::class)->select($this->connection, $token, self::rs256(), Clients::browser());

        self::assertCount(5, $this->recordedEvents());
        self::assertCount(2, $seen);

        $reported = [
            ...array_map(static fn (SsoEvent $event): string => serialize($event) . json_encode($event), $this->recordedEvents()),
            ...array_map(static fn (mixed $result): string => (string) json_encode($result), $results),
        ];

        foreach ($reported as $report) {
            foreach ([...$needles, ...$seen->getArrayCopy()] as $needle) {
                self::assertStringNotContainsString($needle, $report);
            }
        }

        $this->assertNothingLoggedContains(...[...$needles, ...$seen->getArrayCopy()]);
    }

    /**
     * The context every event of the connection names, with the given actor and
     * no flow identifier.
     *
     * @param  ?string  $actingIdentityId
     * @return array<string, ?string>
     */
    private function context(?string $actingIdentityId): array
    {
        return [
            'occurred_at'                 => '2026-11-01T09:30:00.000000Z',
            'ip'                          => '203.0.113.7',
            'user_agent'                  => Clients::USER_AGENT,
            'connection_id'               => $this->connection->id,
            'connection_tenant_id'        => self::TENANT,
            'protocol'                    => 'oidc',
            'application'                 => null,
            'purpose'                     => null,
            'request_reference'           => null,
            'identity_morph_class'        => null,
            'identity_id'                 => null,
            'acting_identity_morph_class' => $actingIdentityId === null ? null : 'App\Models\User',
            'acting_identity_id'          => $actingIdentityId,
            'principal_morph_class'       => null,
            'principal_id'                => null,
            'tenant_id'                   => null,
            'session_id'                  => null,
            'method'                      => null,
        ];
    }

    /**
     * The connection as stored now, read on the write connection.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function row(): Connection
    {
        return Connection::query()->useWritePdo()->findOrFail($this->connection->id);
    }

    /**
     * The refresher, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\MetadataRefresher
     */
    private function refresher(): MetadataRefresher
    {
        return app(MetadataRefresher::class);
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
     * The key's modulus, as its JWK gives it.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $key
     * @return string
     */
    private static function modulusOf(FakeSigningKey $key): string
    {
        $modulus = $key->jwk()['n'] ?? null;

        return is_string($modulus) ? $modulus : self::fail('The key has no modulus.');
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
