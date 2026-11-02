<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\SubjectMigration;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Metadata\ProviderKeys;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Enums\KeySelectionOutcome;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\JwsSigner;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for what an update of an OIDC connection's issuer or JWKS URI
 * clears, in the same locked transaction as the rest of the change (SSO-2.13):
 * the stored keys, their cooldown and a refetch's token, raising their version;
 * for an issuer, the discovery document's refresh dates too. Keys fetched for
 * another issuer or URL are never used. Any other change, one that changes
 * nothing and a refused one clear nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionService::class)]
#[CoversClass(ProviderKeys::class)]
final class OidcTrustResetTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var string The tenant the connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var string The issuer the connection holds. */
    private const string ISSUER = FakeOpenIdProvider::ISSUER;

    /** @var string A time before each test's change. */
    private const string EARLIER = '2026-11-01T09:00:00+00:00';

    /** @var string A time after each test's change. */
    private const string LATER = '2026-11-01T10:00:00+00:00';

    /** @var string A token a refetch claimed with. */
    private const string REFETCH_TOKEN = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /** @var string A token a refresh claimed with. */
    private const string REFRESH_TOKEN = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    /** @var string The JWKS the connection stores. */
    private const string JWKS = '[{"kty":"stored"}]';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's key, generated once. */
    private static ?FakeSigningKey $key = null;

    /**
     * Bind a fixed clock and a fresh freshness contract, switch OIDC and the
     * refresh on, and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        config()->set('sso.features.oidc', true);
        config()->set('sso.features.metadata_refresh', true);

        $this->createConnectionTables();
        $this->createFlowTables();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * Rows of `[settings changed, keys cleared, dates cleared, trust raised]`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool, 2: bool, 3: bool}>
     */
    public static function provideChanges(): iterable
    {
        yield from [
            'the issuer'              => [['issuer' => 'https://new.example.test'], true, true, true],
            'the JWKS URI'            => [['jwks_uri' => 'https://new.example.test/jwks'], true, false, true],
            'the issuer and JWKS URI' => [['issuer' => 'https://new.example.test', 'jwks_uri' => 'https://new.example.test/jwks'], true, true, true],
            'the token endpoint'      => [['token_endpoint' => 'https://new.example.test/token'], false, false, true],
            'the client secret'       => [['client_secret' => 'a-new-secret-value'], false, false, true],
            'the scopes'              => [['scopes' => ['openid', 'groups']], false, false, false],
        ];
    }

    /**
     * An update of the issuer or the JWKS URI clears the keys and raises their
     * version, an issuer's also the discovery document's refresh dates, and
     * sets nothing else; any other change clears nothing. The trust version
     * rises once and what is in flight is voided by each trust change alone.
     *
     * @param  array<string, mixed>  $settings
     * @param  bool  $keys
     * @param  bool  $dates
     * @param  bool  $trust
     * @return void
     */
    #[DataProvider('provideChanges')]
    public function testAnUpdateClearsExactlyWhatWasFetchedForTheIssuerOrUrl(array $settings, bool $keys, bool $dates, bool $trust): void
    {
        $connection = $this->connection();
        $request    = $this->makeAuthorizationRequest($connection);
        $code       = $this->makeHandoffCode($connection);
        $before     = self::state($this->row($connection));

        $result = $this->service()->update(self::TENANT, $connection->id, ['settings' => $settings]);

        self::assertSame(ConnectionStatus::UPDATED, $result->status);

        $expected = [
            ...$before,
            ...($keys ? ['jwks' => null, 'jwks_version' => 4, 'jwks_fetched_at' => null, 'jwks_refetch_at' => null, 'jwks_claim_token' => null] : []),
            ...($dates ? ['metadata_fetched_at' => null, 'metadata_valid_until' => null, 'metadata_refresh_at' => null] : []),
            'trust_version' => $trust ? 3 : 2,
        ];

        self::assertSame($expected, self::state($this->row($connection)));
        self::assertSame($trust, $request->refresh()->voided_at !== null);
        self::assertSame($trust, $code->refresh()->voided_at !== null);
    }

    /**
     * An update that gives what is stored changes nothing and clears nothing.
     *
     * @return void
     */
    public function testAnUpdateThatChangesNothingClearsNothing(): void
    {
        $connection = $this->connection();
        $before     = self::state($this->row($connection));

        $result = $this->service()->update(self::TENANT, $connection->id, ['settings' => ['issuer' => self::ISSUER, 'jwks_uri' => self::ISSUER . '/jwks']]);

        self::assertSame(ConnectionStatus::UNCHANGED, $result->status);
        self::assertSame($before, self::state($this->row($connection)));
    }

    /**
     * A change refused as invalid clears nothing.
     *
     * @return void
     */
    public function testAnInvalidChangeClearsNothing(): void
    {
        $connection = $this->connection();
        $before     = self::state($this->row($connection));

        $result = $this->service()->update(self::TENANT, $connection->id, ['settings' => ['issuer' => 'http://new.example.test']]);

        self::assertSame(ConnectionStatus::INVALID, $result->status);
        self::assertSame($before, self::state($this->row($connection)));
    }

    /**
     * A caller whose authentication is not fresh enough clears nothing.
     *
     * @return void
     */
    public function testAStaleCallerClearsNothing(): void
    {
        $this->app?->instance(Freshness::class, FakeFreshness::stale());

        $connection = $this->connection();
        $before     = self::state($this->row($connection));

        $result = $this->service()->update(self::TENANT, $connection->id, ['settings' => ['jwks_uri' => 'https://new.example.test/jwks']]);

        self::assertSame([ConnectionStatus::REFUSED, FailureReason::FRESHNESS_REQUIRED], [$result->status, $result->reason]);
        self::assertSame($before, self::state($this->row($connection)));
    }

    /**
     * An issuer change refused for the connection's links clears nothing, and
     * one made through a subject migration clears as an update does.
     *
     * @return void
     */
    public function testAnIssuerChangeThroughAMigrationClearsAsAnUpdateDoes(): void
    {
        $connection = $this->connection();
        $link       = $this->makeLink($connection);
        $before     = self::state($this->row($connection));
        $changes    = ['settings' => ['issuer' => 'https://new.example.test']];

        $refused = $this->service()->update(self::TENANT, $connection->id, $changes);

        self::assertSame([ConnectionStatus::REFUSED, FailureReason::CONNECTION_HAS_LINKS], [$refused->status, $refused->reason]);
        self::assertSame($before, self::state($this->row($connection)));

        $migrated = app(SubjectMigration::class)->migrate(self::TENANT, $connection->id, $changes, [], [$link->id]);

        self::assertSame(ConnectionStatus::MIGRATED, $migrated->status);
        self::assertSame([
            ...$before,
            'jwks'                 => null,
            'jwks_version'         => 4,
            'jwks_fetched_at'      => null,
            'jwks_refetch_at'      => null,
            'jwks_claim_token'     => null,
            'metadata_fetched_at'  => null,
            'metadata_valid_until' => null,
            'metadata_refresh_at'  => null,
            'trust_version'        => 3,
        ], self::state($this->row($connection)));
    }

    /**
     * A key fetched for the URL before is never used: the next unknown `kid`
     * refetches at once, the cooldown cleared, from the new URL alone.
     *
     * @return void
     */
    public function testKeysFetchedForAnotherUrlAreNeverUsed(): void
    {
        $fetcher  = new FakeFetcher;
        $provider = (new FakeOpenIdProvider('https://new.example.test', FakeSigningKey::ec('new')))->serve($fetcher);
        $allowed  = AlgorithmAllowList::of(['RS256']);
        $jwks     = ProviderKeySet::read((string) json_encode(['keys' => [self::key()->jwk()]]), $allowed, 65536, 50)?->toStored();

        $this->app?->instance(Fetcher::class, $fetcher);

        $connection = $this->connection(['jwks' => $jwks]);
        $token      = CompactToken::parse(JwsSigner::sign(['alg' => 'RS256', 'kid' => 'rsa-1'], ['sub' => 'a'], self::key()), 16384);

        self::assertInstanceOf(CompactToken::class, $token);
        self::assertSame(KeySelectionOutcome::FOUND, app(ProviderKeys::class)->select($connection, $token, $allowed)->outcome);

        $this->service()->update(self::TENANT, $connection->id, ['settings' => ['jwks_uri' => $provider->endpoint('jwks')]]);

        self::assertSame(KeySelectionOutcome::UNKNOWN, app(ProviderKeys::class)->select($connection, $token, $allowed)->outcome);
        self::assertSame([$provider->endpoint('jwks')], array_map(static fn (FetchRequest $request): string => $request->url, $fetcher->requests()));
    }

    /**
     * An OIDC connection with keys and refresh state to clear, and a trust
     * version of two, the attributes given laid over them.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connection(array $attributes = []): Connection
    {
        $earlier = CarbonImmutable::parse(self::EARLIER);
        $later   = CarbonImmutable::parse(self::LATER);

        return $this->makeConnection([
            'settings' => OidcSettings::fromArray([
                'issuer'                 => self::ISSUER,
                'authorization_endpoint' => self::ISSUER . '/authorize',
                'token_endpoint'         => self::ISSUER . '/token',
                'jwks_uri'               => self::ISSUER . '/jwks',
                'client_id'              => FakeOpenIdProvider::CLIENT_ID,
                'metadata_refresh'       => true,
            ])->toArray(),
            'trust_version'             => 2,
            'jwks'                      => self::JWKS,
            'jwks_version'              => 3,
            'jwks_fetched_at'           => $earlier,
            'jwks_refetch_at'           => $later,
            'jwks_claim_token'          => self::REFETCH_TOKEN,
            'metadata_version'          => 5,
            'metadata_fetched_at'       => $earlier,
            'metadata_valid_until'      => $later,
            'metadata_refresh_at'       => $later,
            'metadata_refresh_failures' => 1,
            'metadata_claimed_until'    => $later,
            'metadata_claim_token'      => self::REFRESH_TOKEN,
            ...$attributes,
        ]);
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
     * The service, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionService
     */
    private function service(): ConnectionService
    {
        return app(ConnectionService::class);
    }

    /**
     * Everything a trust reset may touch, and what it must not.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $row
     * @return array<string, mixed>
     */
    private static function state(Connection $row): array
    {
        return [
            'jwks'                      => $row->jwks,
            'jwks_version'              => $row->jwks_version,
            'jwks_fetched_at'           => $row->jwks_fetched_at?->toIso8601String(),
            'jwks_refetch_at'           => $row->jwks_refetch_at?->toIso8601String(),
            'jwks_claim_token'          => $row->jwks_claim_token,
            'trust_version'             => $row->trust_version,
            'metadata_version'          => $row->metadata_version,
            'metadata_fetched_at'       => $row->metadata_fetched_at?->toIso8601String(),
            'metadata_valid_until'      => $row->metadata_valid_until?->toIso8601String(),
            'metadata_refresh_at'       => $row->metadata_refresh_at?->toIso8601String(),
            'metadata_refresh_failures' => $row->metadata_refresh_failures,
            'metadata_claimed_until'    => $row->metadata_claimed_until?->toIso8601String(),
            'metadata_claim_token'      => $row->metadata_claim_token,
        ];
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
}
