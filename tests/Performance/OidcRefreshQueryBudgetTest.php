<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Metadata\DiscoveryImport;
use SineMacula\Laravel\Sso\Metadata\DiscoveryImporter;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\JwksRefetcher;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\OidcMetadataSource;
use SineMacula\Laravel\Sso\Metadata\ProviderKeys;
use SineMacula\Laravel\Sso\Metadata\RefreshResult;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Enums\KeySelectionOutcome;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\KeySelection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\JwsSigner;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;

/**
 * Query budgets for an import, a refetch and a refresh of an OIDC connection
 * (SSO-2.8, SSO-7.3, SSO-11.12).
 *
 * A selection reads the connection on the write connection. Only one that is
 * unknown refetches: it claims the cooldown with one conditional update, then,
 * in one transaction, reads the connection locked and writes only what changed:
 *
 * - a key the stored JWKS holds: 1 read;
 * - a token already disqualified on its unverified claims, whose `kid` the
 *   stored JWKS does not hold: 1 read, nothing claimed or fetched;
 * - a refetch adding a key: 2 reads (the connection, then locked) and 2 writes
 *   (the claim, the keys);
 * - a refetch removing a key: 2 reads and 5 writes (the claim, the keys, the
 *   requests and the handoff codes voided, the trust version raised), and 3
 *   reads when a consumed request asked, its row read with a lock;
 * - a failed refetch: 2 reads and 2 writes (the claim, the token cleared);
 * - a refetch the cooldown holds: 2 reads (the connection, what is stored now)
 *   and 2 writes (the claim's update, which changes no row, and the count of
 *   what it turned away), or 1 write once that count is at its cap.
 *
 * A refresh reads nothing for its snapshot, which its connection holds:
 *
 * - a scheduled refresh adding a key: 2 reads (the listing, the connection
 *   locked) and 2 writes (the claim, the refresh);
 * - a refresh now adding a key: 2 reads (the connection, then locked) and 4
 *   writes (the counter's two, the claim, the refresh);
 * - a refresh now removing a key and moving an endpoint: 2 reads and 7 writes
 *   (the counter's two, the claim, the requests and handoff codes voided, the
 *   trust version raised once, the refresh in one update);
 * - a failed refresh now: 2 reads and 4 writes (the counter's two, the claim,
 *   the failure);
 * - a refresh now whose claim another server holds: 1 read and 3 writes (the
 *   counter's two, the claim's update, which changes no row);
 * - a refresh now past the metadata limit: 2 reads (the connection, the full
 *   counter for its wait) and the counter's 3 writes, none of which changes a
 *   row;
 * - a stale administrator's refresh the schedule would not make: 1 read and no
 *   write, nothing counted or claimed;
 * - a scheduled refresh of keys alone adding a key: 2 reads and 2 writes;
 * - a refresh now of keys alone removing a key: 2 reads and 7 writes (the
 *   counter's two, the claim, the requests and handoff codes voided, the trust
 *   version raised once, the refresh);
 * - a document that fails, then the saved JWKS: as one that does not fail, the
 *   fallback reading and writing nothing more.
 *
 * An import reads nothing naming no connection; naming one, it reads it once
 * and writes the counter's two.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProviderKeys::class)]
#[CoversClass(JwksRefetcher::class)]
#[CoversClass(OidcMetadataSource::class)]
#[CoversClass(DiscoveryImporter::class)]
final class OidcRefreshQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var string The tenant whose connection refreshes. */
    private const string TENANT = 'tenant-1';

    /** @var string The issuer the connection is pinned to. */
    private const string ISSUER = FakeOpenIdProvider::ISSUER;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's key, generated once. */
    private static ?FakeSigningKey $key = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's next key, generated once. */
    private static ?FakeSigningKey $next = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher everything fetches through. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider. */
    private FakeOpenIdProvider $provider;

    /**
     * Bind a fake fetcher serving the provider, and switch OIDC and the refresh
     * on.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher  = new FakeFetcher;
        $this->provider = (new FakeOpenIdProvider(self::ISSUER, self::key()))->serve($this->fetcher);

        $this->app?->instance(Fetcher::class, $this->fetcher);

        config()->set('sso.features.oidc', true);
        config()->set('sso.features.metadata_refresh', true);
    }

    /**
     * A key the stored JWKS holds is one read.
     *
     * @return void
     */
    public function testAKeyStoredIsOneRead(): void
    {
        $connection = $this->oidc([self::key()]);
        $selection  = $this->assertQueryBudget(1, 0, fn (): KeySelection => $this->selected($connection, 'rsa-1'));

        self::assertSame(KeySelectionOutcome::FOUND, $selection->outcome);
    }

    /**
     * A token already disqualified whose `kid` is unknown is one read and no
     * write: nothing is claimed or fetched.
     *
     * @return void
     */
    public function testADisqualifiedTokenIsOneRead(): void
    {
        $connection = $this->oidc([self::key()]);
        $select     = static fn (): KeySelection => app(ProviderKeys::class)->select($connection, self::token('rsa-2'), self::rs256(), null, static fn (): bool => true);
        $selection  = $this->assertQueryBudget(1, 0, $select);

        self::assertSame(KeySelectionOutcome::UNKNOWN, $selection->outcome);

        $this->fetcher->assertNothingFetched();
    }

    /**
     * A refetch adding a key is two reads and two writes.
     *
     * @return void
     */
    public function testARefetchAddingAKeyIsTwoReadsAndTwoWrites(): void
    {
        $connection = $this->oidc([self::key()]);

        $this->provider->publish(self::next());

        $selection = $this->assertQueryBudget(2, 2, fn (): KeySelection => $this->selected($connection, 'rsa-2'));

        self::assertSame(KeySelectionOutcome::FOUND, $selection->outcome);
        self::assertSame(0, $this->row($connection)->trust_version);
    }

    /**
     * A refetch removing a key is two reads and five writes, the trust version
     * raised once.
     *
     * @return void
     */
    public function testARefetchRemovingAKeyIsTwoReadsAndFiveWrites(): void
    {
        $connection = $this->oidc([self::key(), self::next()]);

        $this->assertQueryBudget(2, 5, fn (): KeySelection => $this->selected($connection, 'rsa-3'));

        self::assertSame(1, $this->row($connection)->trust_version);
    }

    /**
     * A refetch removing a key for the consumed request whose token asked adds
     * the locking read of that request, and answers its receipt.
     *
     * @return void
     */
    public function testARefetchRemovingAKeyForARequestIsThreeReadsAndFiveWrites(): void
    {
        $connection = $this->oidc([self::next()]);
        $request    = $this->makeAuthorizationRequest($connection, ['consumed_at' => $this->clock->now()]);
        $consumed   = new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::fromString($request->reference), $this->clock->now());

        $selection = $this->assertQueryBudget(3, 5, fn (): KeySelection => app(ProviderKeys::class)->select($connection, self::token('rsa-1'), self::rs256(), $consumed));

        self::assertSame(KeySelectionOutcome::FOUND, $selection->outcome);
        self::assertNotNull($selection->receipt);
    }

    /**
     * A failed refetch is two reads and two writes.
     *
     * @return void
     */
    public function testAFailedRefetchIsTwoReadsAndTwoWrites(): void
    {
        $connection = $this->oidc([self::key()]);

        $this->provider->respond('jwks', FetchResult::failed());

        self::assertSame(KeySelectionOutcome::UNKNOWN, $this->assertQueryBudget(2, 2, fn (): KeySelection => $this->selected($connection, 'rsa-2'))->outcome);
    }

    /**
     * A refetch the cooldown holds is two reads and two writes, and fetches
     * nothing.
     *
     * @return void
     */
    public function testARefetchTheCooldownHoldsIsTwoReadsAndTwoWrites(): void
    {
        $connection = $this->oidc([self::key()], ['jwks_refetch_at' => $this->clock->now()->addMinute()]);

        self::assertSame(KeySelectionOutcome::UNKNOWN, $this->assertQueryBudget(2, 2, fn (): KeySelection => $this->selected($connection, 'rsa-2'))->outcome);

        $this->fetcher->assertNothingFetched();
    }

    /**
     * Once the count of what the cooldown turned away is at its cap, a token is
     * two reads and the failed claim, which changes no row: the row is not
     * written at all.
     *
     * @return void
     */
    public function testARefetchTheCooldownHoldsAtItsCountsCapIsTwoReadsAndOneWrite(): void
    {
        $connection = $this->oidc([self::key()], ['jwks_refetch_at' => $this->clock->now()->addMinute(), 'jwks_refetch_suppressed' => JwksRefetcher::MAX_COUNTED_SUPPRESSED]);

        self::assertSame(KeySelectionOutcome::UNKNOWN, $this->assertQueryBudget(2, 1, fn (): KeySelection => $this->selected($connection, 'rsa-2'))->outcome);

        $this->fetcher->assertNothingFetched();
    }

    /**
     * A scheduled refresh adding a key is two reads and two writes.
     *
     * @return void
     */
    public function testAScheduledRefreshAddingAKeyIsTwoReadsAndTwoWrites(): void
    {
        $this->oidc([self::key()]);
        $this->provider->publish(self::next());

        $results = $this->assertQueryBudget(2, 2, fn (): array => $this->refresher()->refreshDue());

        self::assertSame([RefreshOutcome::REFRESHED], array_map(static fn (RefreshResult $result): RefreshOutcome => $result->outcome, $results));
    }

    /**
     * A refresh now adding a key is two reads and four writes.
     *
     * @return void
     */
    public function testARefreshAddingAKeyIsTwoReadsAndFourWrites(): void
    {
        $connection = $this->oidc([self::key()]);

        $this->provider->publish(self::next());

        $result = $this->assertQueryBudget(2, 4, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor()));

        self::assertSame([RefreshOutcome::REFRESHED, ['jwks'], false], [$result->outcome, $result->changedSettings, $result->trustChanged]);
    }

    /**
     * A refresh now removing a key and moving an endpoint is two reads and
     * seven writes, the trust version raised once.
     *
     * @return void
     */
    public function testARefreshRemovingAKeyAndMovingAnEndpointIsTwoReadsAndSevenWrites(): void
    {
        $connection = $this->oidc([self::key(), self::next()]);

        $this->provider->withDiscovery(['token_endpoint' => 'https://moved.example.test/token']);

        $result = $this->assertQueryBudget(2, 7, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor()));

        self::assertSame([RefreshOutcome::REFRESHED, ['token_endpoint', 'jwks'], true], [$result->outcome, $result->changedSettings, $result->trustChanged]);
        self::assertSame(1, $this->row($connection)->trust_version);
    }

    /**
     * A failed refresh now is two reads and four writes.
     *
     * @return void
     */
    public function testAFailedRefreshIsTwoReadsAndFourWrites(): void
    {
        $connection = $this->oidc([self::key()], ['metadata_fetched_at' => $this->clock->now()->subDay()]);

        $this->provider->respond('discovery', FetchResult::failed());

        $result = $this->assertQueryBudget(2, 4, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor()));

        self::assertSame(RefreshOutcome::FAILED, $result->outcome);
    }

    /**
     * A refresh now whose claim another server holds is one read and three
     * writes, and fetches nothing.
     *
     * @return void
     */
    public function testARefreshWhoseClaimIsHeldIsOneReadAndThreeWrites(): void
    {
        $connection = $this->oidc([self::key()], ['metadata_claimed_until' => $this->clock->now()->addMinute()]);

        $result = $this->assertQueryBudget(1, 3, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor()));

        self::assertSame(RefreshOutcome::IN_PROGRESS, $result->outcome);

        $this->fetcher->assertNothingFetched();
    }

    /**
     * A refresh now past the metadata limit is two reads and the counter's
     * three writes, and claims and fetches nothing.
     *
     * @return void
     */
    public function testARateLimitedRefreshIsTwoReadsAndThreeWrites(): void
    {
        config()->set('sso.rate_limits.metadata.per_connection', ['max' => 1, 'decay_seconds' => 3600]);

        $connection = $this->oidc([self::key()], ['metadata_claimed_until' => $this->clock->now()->addMinute()]);

        $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor());

        $result = $this->assertQueryBudget(2, 3, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor()));

        self::assertSame(RefreshOutcome::RATE_LIMITED, $result->outcome);

        $this->fetcher->assertNothingFetched();
    }

    /**
     * A stale administrator's refresh the schedule would not make is the read
     * of the connection alone: nothing is counted, claimed or fetched.
     *
     * @return void
     */
    public function testAStaleRefreshIsOneRead(): void
    {
        $connection = $this->oidc([self::key()], ['metadata_fetched_at' => $this->clock->now()->subDay()], ['metadata_refresh' => false]);

        $this->app?->instance(Freshness::class, FakeFreshness::stale());

        $result = $this->assertQueryBudget(1, 0, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor()));

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);

        $this->fetcher->assertNothingFetched();
    }

    /**
     * A scheduled refresh of keys alone adding a key is two reads and two
     * writes.
     *
     * @return void
     */
    public function testAScheduledRefreshOfKeysAloneIsTwoReadsAndTwoWrites(): void
    {
        $this->oidc([self::key()], ['jwks_fetched_at' => $this->clock->now()], ['metadata_refresh' => false]);
        $this->provider->publish(self::next());

        $results = $this->assertQueryBudget(2, 2, fn (): array => $this->refresher()->refreshDue());

        self::assertSame([RefreshOutcome::REFRESHED], array_map(static fn (RefreshResult $result): RefreshOutcome => $result->outcome, $results));
    }

    /**
     * A refresh now of keys alone removing a key is two reads and seven writes,
     * the trust version raised once.
     *
     * @return void
     */
    public function testARefreshOfKeysAloneRemovingAKeyIsTwoReadsAndSevenWrites(): void
    {
        $connection = $this->oidc([self::key(), self::next()], ['jwks_fetched_at' => $this->clock->now()], ['metadata_refresh' => false]);

        $result = $this->assertQueryBudget(2, 7, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor()));

        self::assertSame([RefreshOutcome::REFRESHED, ['jwks'], true], [$result->outcome, $result->changedSettings, $result->trustChanged]);
        self::assertSame(1, $this->row($connection)->trust_version);
    }

    /**
     * A document that fails, then the saved JWKS, costs what a refresh of keys
     * alone does: the fallback reads and writes nothing more.
     *
     * @return void
     */
    public function testAFallbackToTheSavedKeysIsTwoReadsAndFourWrites(): void
    {
        $connection = $this->oidc([self::key()]);

        $this->provider->respond('discovery', FetchResult::failed());

        $result = $this->assertQueryBudget(2, 4, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor()));

        self::assertSame(RefreshOutcome::REFRESHED, $result->outcome);
    }

    /**
     * An import naming no connection touches no table.
     *
     * @return void
     */
    public function testAnImportNamingNoConnectionTouchesNoTable(): void
    {
        $result = $this->assertQueryBudget(0, 0, fn (): DiscoveryImport => app(DiscoveryImporter::class)->import(self::TENANT, self::ISSUER));

        self::assertTrue($result->isProposed());
    }

    /**
     * An import naming a connection reads it and writes the counter's two.
     *
     * @return void
     */
    public function testAnImportNamingAConnectionIsOneReadAndTwoWrites(): void
    {
        $connection = $this->oidc([self::key()]);
        $result     = $this->assertQueryBudget(1, 2, fn (): DiscoveryImport => app(DiscoveryImporter::class)->import(self::TENANT, self::ISSUER, $connection->id));

        self::assertTrue($result->isProposed());
    }

    /**
     * What selecting the key of a token under the `kid` chose.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $kid
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\KeySelection
     */
    private function selected(Connection $connection, string $kid): KeySelection
    {
        return app(ProviderKeys::class)->select($connection, self::token($kid), self::rs256());
    }

    /**
     * A refreshing connection of the tenant storing the keys, with the
     * attributes and settings given.
     *
     * @param  list<\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey>  $keys
     * @param  array<string, mixed>  $attributes
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function oidc(array $keys, array $attributes = [], array $settings = []): Connection
    {
        return $this->makeConnection([
            'jwks'     => self::stored($keys),
            'settings' => OidcSettings::fromArray([
                'issuer'                 => self::ISSUER,
                'authorization_endpoint' => self::ISSUER . '/authorize',
                'token_endpoint'         => self::ISSUER . '/token',
                'jwks_uri'               => self::ISSUER . '/jwks',
                'userinfo_endpoint'      => self::ISSUER . '/userinfo',
                'returns_iss'            => true,
                'client_id'              => FakeOpenIdProvider::CLIENT_ID,
                'metadata_refresh'       => true,
                ...$settings,
            ])->toArray(),
            ...$attributes,
        ]);
    }

    /**
     * The connection as stored now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function row(Connection $connection): Connection
    {
        return Connection::query()->findOrFail($connection->id);
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

    /**
     * The administrator who asks for a refresh now.
     *
     * @return \SineMacula\Laravel\Sso\Administration\ActingIdentity
     */
    private static function actor(): ActingIdentity
    {
        return new ActingIdentity('App\Models\User', '42');
    }
}
