<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Bus;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\FetchedMetadata;
use SineMacula\Laravel\Sso\Metadata\MetadataExpiry;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\OidcMetadata;
use SineMacula\Laravel\Sso\Metadata\OidcMetadataSource;
use SineMacula\Laravel\Sso\Metadata\RefreshClaim;
use SineMacula\Laravel\Sso\Metadata\RefreshConnectionMetadata;
use SineMacula\Laravel\Sso\Metadata\RefreshResult;
use SineMacula\Laravel\Sso\Metadata\RefreshWriter;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the scheduled and administrator's refresh of an OIDC
 * connection's discovery document and JWKS (SSO-2.8, SSO-2.13, SSO-7.3,
 * SSO-11.12), through the shared machinery with the fake provider: which
 * connections refresh, the snapshot and claim, each resource's validated
 * moment, the issuer pinned, what a refresh may and may never change, exact
 * replacement of the keys, when it voids and raises the trust version, its
 * refusals under the lock, and the compare and set.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OidcMetadataSource::class)]
#[CoversClass(OidcMetadata::class)]
#[CoversClass(RefreshWriter::class)]
final class OidcMetadataSourceTest extends TestCase
{
    use CapturesLogs, RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The tenant whose connection refreshes. */
    private const string TENANT = 'tenant-1';

    /** @var string The issuer every connection is pinned to. */
    private const string ISSUER = FakeOpenIdProvider::ISSUER;

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T09:30:00+00:00';

    /** @var string When a refresh at the start is next due. */
    private const string TOMORROW = '2026-11-02T09:30:00+00:00';

    /** @var string When a failure at the start is next tried. */
    private const string BACKOFF = '2026-11-01T09:35:00+00:00';

    /** @var string A URL the provider's document may move a setting to. */
    private const string MOVED = 'https://moved.example.test/endpoint';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's key, generated once. */
    private static ?FakeSigningKey $key = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's next key, generated once. */
    private static ?FakeSigningKey $next = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the refresh fetches through. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider refreshed from. */
    private FakeOpenIdProvider $provider;

    /**
     * Bind a fixed clock and a fake fetcher serving the provider, switch OIDC
     * and the refresh on, create the tables and capture logs.
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

        config()->set('sso.features.oidc', true);
        config()->set('sso.features.metadata_refresh', true);

        $this->usePackageTables();

        $this->captureLogs();
    }

    /**
     * Rows of `[attributes, settings, refreshes]`: which connections refresh.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: bool}>
     */
    public static function provideRefreshingConnections(): iterable
    {
        $at   = CarbonImmutable::parse(self::NOW);
        $keys = ['jwks_fetched_at' => $at];
        $off  = ['metadata_refresh' => false];

        yield from [
            'its switch on and a valid issuer' => [[], [], true],
            'its switch off'                   => [[], ['metadata_refresh' => false], false],
            'its switch not true'              => [[], ['metadata_refresh' => 'true'], false],
            'no switch'                        => [[], ['metadata_refresh' => null], false],
            'an http issuer'                   => [[], ['issuer' => 'http://op.example.test'], false],
            'an issuer with a query'           => [[], ['issuer' => self::ISSUER . '?a=1'], false],
            'no issuer'                        => [[], ['issuer' => null], false],
            'an issuer not a string'           => [[], ['issuer' => 1], false],
            'a SAML connection'                => [['protocol' => 'saml2'], [], false],
            'off, keys fetched, no document'   => [$keys, $off, true],
            'off, no keys fetched yet'         => [[], $off, false],
            'off, keys fetched, a document'    => [[...$keys, 'metadata_fetched_at' => $at], $off, false],
            'off, keys fetched, no JWKS URL'   => [$keys, [...$off, 'jwks_uri' => null], false],
            'off, keys fetched, bad JWKS URL'  => [$keys, [...$off, 'jwks_uri' => 'http://op.example.test/jwks'], false],
            'off, keys fetched, bad issuer'    => [$keys, [...$off, 'issuer' => 'http://op.example.test'], false],
        ];
    }

    /**
     * A connection refreshes while it is OIDC, its switch is on and its issuer
     * is valid, and is then listed as due.
     *
     * @param  array<string, mixed>  $attributes
     * @param  array<string, mixed>  $settings
     * @param  bool  $refreshes
     * @return void
     */
    #[DataProvider('provideRefreshingConnections')]
    public function testWhichConnectionsRefresh(array $attributes, array $settings, bool $refreshes): void
    {
        $connection = $this->oidc($settings, $attributes);

        self::assertSame('oidc', $this->source()->protocol());
        self::assertSame($refreshes, $this->source()->refreshes($connection));
        self::assertSame($refreshes ? [$connection->id] : [], $this->refresher()->dueConnectionIds());
    }

    /**
     * A due OIDC connection is queued by the command, and the job refreshes it.
     *
     * @return void
     */
    public function testADueConnectionIsQueuedAndItsJobRefreshesIt(): void
    {
        Bus::fake();

        $connection = $this->oidc();
        $code       = Artisan::call('sso:metadata:refresh');

        self::assertSame([0, 'Metadata refreshes queued: 1'], [$code, trim(Artisan::output())]);

        Bus::assertDispatched(RefreshConnectionMetadata::class, static fn (RefreshConnectionMetadata $job): bool => $job->connectionId === $connection->id);

        $this->fetcher->assertNothingFetched();

        self::assertSame(RefreshOutcome::REFRESHED, $this->refresher()->refreshQueued($connection->id, Clients::browser())->outcome);
        self::assertSame(RefreshOutcome::SKIPPED, $this->refresher()->refreshQueued($connection->id, Clients::browser())->outcome);
    }

    /**
     * The claim holds the snapshot, in a fixed order whatever order the
     * settings were saved in, with a setting not held as `null`, and writes its
     * token; a second claim while it holds is `null`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheClaimSnapshotsTheTrustInAFixedOrder(): void
    {
        $settings = array_reverse(self::settings(['userinfo_endpoint' => null, 'fetch_userinfo' => false]), true);

        $connection = $this->row($this->makeConnection(['settings' => $settings, 'jwks_version' => 4]));
        $claim      = $this->source()->claim($connection);

        self::assertInstanceOf(RefreshClaim::class, $claim);
        self::assertSame([
            'jwks_version' => 4,
            'settings'     => [
                'issuer'                 => self::ISSUER,
                'authorization_endpoint' => self::ISSUER . '/authorize',
                'token_endpoint'         => self::ISSUER . '/token',
                'jwks_uri'               => self::ISSUER . '/jwks',
                'userinfo_endpoint'      => null,
                'returns_iss'            => true,
                'id_token_algorithms'    => ['RS256'],
                'fetch_userinfo'         => false,
            ],
        ], $claim->trusted);

        $row = $this->row($connection);

        self::assertSame([$claim->token, self::BACKOFF], [$row->metadata_claim_token, $row->metadata_claimed_until?->toIso8601String()]);
        self::assertSame(32, strlen($claim->token));
        self::assertNull($this->source()->claim($connection));
    }

    /**
     * A fetch reads the saved issuer's document, then the JWKS it names, each
     * under its own cap, and notes the moment each validated.
     *
     * @return void
     */
    public function testAFetchNotesEachMomentItValidated(): void
    {
        $clock = $this->clock;

        $this->provider->respond('jwks', function (FetchRequest $request) use ($clock): FetchResult {
            unset($request);

            $clock->advance(7);

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });

        $connection = $this->oidc();
        $fetched    = $this->source()->fetch(new RefreshClaim($connection, 'token', []));
        $metadata   = $fetched->document();

        self::assertInstanceOf(OidcMetadata::class, $metadata);
        self::assertSame([self::NOW, '2026-11-01T09:30:07+00:00'], [$fetched->validatedAt?->toIso8601String(), $metadata->keysValidatedAt->toIso8601String()]);
        self::assertSame(FetchStatus::FETCHED, $fetched->fetchStatus);
        self::assertSame(self::ISSUER . '/token', $metadata->document()->settings()['token_endpoint']);
        self::assertSame(['rsa-1'], array_map(static fn (ProviderKey $key): ?string => $key->keyId(), $metadata->keys()->keys));
        self::assertSame([
            ['discovery', self::ISSUER . '/.well-known/openid-configuration', 65536],
            ['jwks', self::ISSUER . '/jwks', 65536],
        ], array_map(static fn (FetchRequest $request): array => [$request->purpose->value, $request->url, $request->maxBytes], $this->fetcher->requests()));
    }

    /**
     * A document naming another issuer is `issuer_mismatch`: a refresh never
     * changes the issuer, keeps the last good settings and fetches no JWKS.
     *
     * @return void
     */
    public function testAFetchIsPinnedToTheSavedIssuer(): void
    {
        $this->provider->withDiscovery(['issuer' => 'https://attacker.example.test', 'token_endpoint' => self::MOVED]);

        $connection = $this->oidc();
        $fetched    = $this->source()->fetch(new RefreshClaim($connection, 'token', []));

        self::assertSame([false, FailureReason::ISSUER_MISMATCH, FetchStatus::FETCHED], [$fetched->isRead(), $fetched->reason, $fetched->fetchStatus]);
        self::assertCount(1, $this->fetcher->requests());

        $result = $this->refreshDue();

        self::assertSame([RefreshOutcome::FAILED, FailureReason::ISSUER_MISMATCH], [$result->outcome, $result->reason]);
        self::assertEquals(self::settings(), $this->row($connection)->settings);
    }

    /**
     * The JWKS is read under the connection's own allow-list, whatever the
     * document supports.
     *
     * @return void
     */
    public function testAFetchHoldsTheJwksToTheConnectionsAllowList(): void
    {
        $this->provider->respond('jwks', FakeTokenEndpoint::json(200, ['keys' => [self::key()->jwk('RS256')]]));

        $allowed = $this->oidc(['id_token_algorithms' => ['RS256']]);
        $refused = $this->oidc(['id_token_algorithms' => ['PS256']]);

        self::assertTrue($this->source()->fetch(new RefreshClaim($allowed, 'token', []))->isRead());

        $fetched = $this->source()->fetch(new RefreshClaim($refused, 'token', []));

        self::assertSame([false, FailureReason::JWKS_INVALID, FetchStatus::FETCHED], [$fetched->isRead(), $fetched->reason, $fetched->fetchStatus]);
    }

    /**
     * An allow-list that cannot be built from what is stored is contained: the
     * refresh records `settings_invalid`, nothing is fetched, and the exception
     * is logged by its class alone, so a run goes on to the next connection.
     *
     * @return void
     */
    public function testAnAllowListThatCannotBeBuiltIsContained(): void
    {
        $connection = $this->oidc(['id_token_algorithms' => ['HS256']]);
        $result     = $this->refreshDue();

        self::assertSame([RefreshOutcome::FAILED, FailureReason::SETTINGS_INVALID, 1], [$result->outcome, $result->reason, $result->failures]);
        self::assertSame(1, $this->row($connection)->metadata_refresh_failures);
        self::assertSame([
            ['warning', 'sso.metadata.refresh_contained', ['exception' => \InvalidArgumentException::class]],
            ['warning', 'sso.metadata.refresh_failed', ['reason' => 'settings_invalid', 'fetch_status' => 'refused']],
        ], array_map(static fn (array $record): array => [$record['level'], $record['message'], $record['context']], $this->capturedLogRecords()));

        $this->fetcher->assertNothingFetched();
    }

    /**
     * A claim on a connection with no issuer fetches nothing.
     *
     * @return void
     */
    public function testAFetchWithNoIssuerFetchesNothing(): void
    {
        $fetched = $this->source()->fetch(new RefreshClaim($this->oidc(['issuer' => null]), 'token', []));

        self::assertSame([FailureReason::SETTINGS_INVALID, FetchStatus::REFUSED], [$fetched->reason, $fetched->fetchStatus]);
        self::assertSame([], $this->capturedLogRecords());

        $this->fetcher->assertNothingFetched();
    }

    /**
     * Keys added alone are written, void nothing and leave the trust version as
     * it was, and the refresh's bookkeeping is written with them.
     *
     * @return void
     */
    public function testAddedKeysVoidNothing(): void
    {
        $connection = $this->oidc([], ['jwks' => self::stored([self::key()])]);
        $request    = $this->makeAuthorizationRequest($connection);
        $code       = $this->makeHandoffCode($connection);

        $this->provider->publish(self::next());

        $result = $this->refreshDue();
        $row    = $this->row($connection);

        self::assertSame([RefreshOutcome::REFRESHED, ['jwks'], 1, false], [$result->outcome, $result->changedSettings, $result->metadataVersion, $result->trustChanged]);
        self::assertSame(self::stored([self::key(), self::next()]), $row->jwks);
        self::assertSame([1, 0, 0, 1, 0], [$row->jwks_version, $row->trust_version, $row->flows_version, $row->metadata_version, $row->metadata_refresh_failures]);
        self::assertSame([self::NOW, self::NOW, self::TOMORROW], [
            $row->metadata_fetched_at?->toIso8601String(),
            $row->jwks_fetched_at?->toIso8601String(),
            $row->metadata_refresh_at?->toIso8601String(),
        ]);
        self::assertSame([null, null, null], [$row->metadata_claim_token, $row->metadata_claimed_until, $row->metadata_valid_until]);
        self::assertNull($request->refresh()->voided_at);
        self::assertNull($code->refresh()->voided_at);
        self::assertEquals(self::settings(), $row->settings);
    }

    /**
     * Nothing changed writes the same keys under the next version and names
     * nothing, with no trust change; the refetch's cooldown is left as it was.
     *
     * @return void
     */
    public function testARefreshThatChangesNothingNamesNothing(): void
    {
        $until      = $this->clock->now()->addMinute();
        $connection = $this->oidc([], ['jwks' => self::stored([self::key()]), 'jwks_refetch_at' => $until, 'jwks_claim_token' => str_repeat('a', 32)]);
        $result     = $this->refreshDue();
        $row        = $this->row($connection);

        self::assertSame([RefreshOutcome::REFRESHED, [], 1, false], [$result->outcome, $result->changedSettings, $result->metadataVersion, $result->trustChanged]);
        self::assertSame([1, 0], [$row->jwks_version, $row->trust_version]);
        self::assertSame(self::stored([self::key()]), $row->jwks);
        self::assertSame(['2026-11-01T09:31:00+00:00', str_repeat('a', 32)], [$row->jwks_refetch_at?->toIso8601String(), $row->jwks_claim_token]);
    }

    /**
     * A key removed is replaced exactly, voids what is in flight and raises the
     * trust version once.
     *
     * @return void
     */
    public function testARemovedKeyVoidsWhatIsInFlight(): void
    {
        $connection = $this->oidc([], ['jwks' => self::stored([self::key(), self::next()])]);
        $request    = $this->makeAuthorizationRequest($connection);
        $code       = $this->makeHandoffCode($connection);

        $result = $this->refreshDue();
        $row    = $this->row($connection);

        self::assertSame([RefreshOutcome::REFRESHED, ['jwks'], true], [$result->outcome, $result->changedSettings, $result->trustChanged]);
        self::assertSame(self::stored([self::key()]), $row->jwks);
        self::assertSame([1, 1], [$row->jwks_version, $row->trust_version]);
        self::assertSame(self::NOW, $request->refresh()->voided_at?->toIso8601String());
        self::assertSame(self::NOW, $code->refresh()->voided_at?->toIso8601String());
    }

    /**
     * A key replaced under its `kid` is replaced, never kept beside, and voids
     * what is in flight, whatever else stands.
     *
     * @return void
     */
    public function testAKeyReplacedUnderItsKidVoids(): void
    {
        $connection = $this->oidc([], ['jwks' => self::stored([self::next()->withKid('rsa-1')])]);
        $request    = $this->makeAuthorizationRequest($connection);
        $result     = $this->refreshDue();
        $row        = $this->row($connection);

        self::assertSame([RefreshOutcome::REFRESHED, ['jwks'], true], [$result->outcome, $result->changedSettings, $result->trustChanged]);
        self::assertSame(self::stored([self::key()]), $row->jwks);
        self::assertSame(1, $row->trust_version);
        self::assertNotNull($request->refresh()->voided_at);
    }

    /**
     * Rows of `[document changes, stored settings, names changed, settings
     * after]`: what a refresh may change.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: list<string>, 3: array<string, mixed>}>
     */
    public static function provideSettingChanges(): iterable
    {
        yield from [
            'the authorisation endpoint moved' => [['authorization_endpoint' => self::MOVED], [], ['authorization_endpoint'], ['authorization_endpoint' => self::MOVED]],
            'the token endpoint moved'         => [['token_endpoint' => self::MOVED], [], ['token_endpoint'], ['token_endpoint' => self::MOVED]],
            'the JWKS moved'                   => [['jwks_uri' => self::MOVED], [], ['jwks_uri'], ['jwks_uri' => self::MOVED]],
            'the UserInfo endpoint moved'      => [['userinfo_endpoint' => self::MOVED], [], ['userinfo_endpoint'], ['userinfo_endpoint' => self::MOVED]],
            'the UserInfo endpoint set'        => [[], ['userinfo_endpoint' => null], ['userinfo_endpoint'], ['userinfo_endpoint' => self::ISSUER . '/userinfo']],
            'the UserInfo endpoint removed'    => [['userinfo_endpoint' => null], [], [], []],
            'iss from false to true'           => [[], ['returns_iss' => false], ['returns_iss'], ['returns_iss' => true]],
            'iss from true to false'           => [['authorization_response_iss_parameter_supported' => false], [], [], []],
            'iss from true to none'            => [['authorization_response_iss_parameter_supported' => null], [], [], []],
            'iss staying false'                => [['authorization_response_iss_parameter_supported' => false], ['returns_iss' => false], [], []],
        ];
    }

    /**
     * A refresh sets or moves an endpoint and turns `returns_iss` on, never
     * removes an endpoint or turns it off; each change voids what is in flight
     * and raises the trust version once, and nothing else does.
     *
     * @param  array<string, mixed>  $changes
     * @param  array<string, mixed>  $stored
     * @param  list<string>  $names
     * @param  array<string, mixed>  $after
     * @return void
     */
    #[DataProvider('provideSettingChanges')]
    public function testWhatARefreshMayChange(array $changes, array $stored, array $names, array $after): void
    {
        $this->provider->withDiscovery($changes);
        $this->fetcher->respond(self::MOVED, FakeTokenEndpoint::json(200, $this->provider->jwks()));

        $connection = $this->oidc($stored, ['jwks' => self::stored([self::key()])]);
        $request    = $this->makeAuthorizationRequest($connection);

        $result = $this->refreshDue();
        $row    = $this->row($connection);

        self::assertSame([RefreshOutcome::REFRESHED, $names, $names !== []], [$result->outcome, $result->changedSettings, $result->trustChanged]);
        self::assertEquals(self::settings([...$stored, ...$after]), $row->settings);
        self::assertSame($names === [] ? 0 : 1, $row->trust_version);
        self::assertSame($names !== [], $request->refresh()->voided_at !== null);
    }

    /**
     * Every setting a refresh may change, and the keys, are named in the order
     * `OidcSetting` names them, then `jwks`, and the trust version rises once.
     *
     * @return void
     */
    public function testEveryChangeIsNamedInOrderAndVoidsOnce(): void
    {
        $moved = static fn (string $path): string => 'https://moved.example.test/' . $path;

        $this->provider->withDiscovery([
            'token_endpoint'         => $moved('token'),
            'userinfo_endpoint'      => $moved('userinfo'),
            'authorization_endpoint' => $moved('authorize'),
            'jwks_uri'               => $moved('jwks'),
        ]);
        $this->fetcher->respond($moved('jwks'), FakeTokenEndpoint::json(200, $this->provider->jwks()));

        $connection = $this->oidc(['returns_iss' => false], ['jwks' => self::stored([self::key(), self::next()])]);
        $result     = $this->refreshDue();

        self::assertSame(['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint', 'returns_iss', 'jwks'], $result->changedSettings);
        self::assertTrue($result->trustChanged);
        self::assertSame(1, $this->row($connection)->trust_version);
    }

    /**
     * Nothing else a connection holds is ever written, whatever the document
     * supports: its issuer, client id and authentication, secrets, scopes,
     * algorithms, mapping and whether it is enabled.
     *
     * @return void
     */
    public function testARefreshChangesNothingElse(): void
    {
        $this->provider->withDiscovery([
            'id_token_signing_alg_values_supported' => ['RS256', 'ES512'],
            'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
            'scopes_supported'                      => ['openid'],
        ]);

        $mapping  = ['email' => 'mail'];
        $settings = [
            'client_id'             => 'the-client',
            'client_authentication' => 'client_secret_post',
            'scopes'                => ['openid', 'groups'],
            'trusted_audiences'     => ['other'],
            'max_age'               => 60,
        ];
        $connection = $this->oidc($settings, ['secrets' => '{"client_secret":"ciphertext"}', 'attribute_mapping' => $mapping, 'enabled' => true]);

        $this->refreshDue();

        $row = $this->row($connection);

        self::assertEquals(self::settings($settings), $row->settings);
        self::assertSame(['{"client_secret":"ciphertext"}', $mapping, true, self::TENANT], [$row->secrets, $row->attribute_mapping, $row->enabled, $row->tenant_id]);
    }

    /**
     * Rows of `[fetch UserInfo, document gives one, refreshed]`: a connection
     * that fetches UserInfo needs an endpoint from the document.
     *
     * @return iterable<string, array{0: bool, 1: bool, 2: bool}>
     */
    public static function provideUserInfoNeeds(): iterable
    {
        yield from [
            'fetched and given'         => [true, true, true],
            'fetched and not given'     => [true, false, false],
            'not fetched and given'     => [false, true, true],
            'not fetched and not given' => [false, false, true],
        ];
    }

    /**
     * A document with no UserInfo endpoint for a connection that fetches
     * UserInfo is `discovery_invalid` under the lock, and keeps the last good
     * settings.
     *
     * @param  bool  $fetches
     * @param  bool  $given
     * @param  bool  $refreshed
     * @return void
     */
    #[DataProvider('provideUserInfoNeeds')]
    public function testAConnectionFetchingUserInfoNeedsItsEndpoint(bool $fetches, bool $given, bool $refreshed): void
    {
        if (!$given) {
            $this->provider->withDiscovery(['userinfo_endpoint' => null]);
        }

        $connection = $this->oidc(['fetch_userinfo' => $fetches], ['jwks' => self::stored([self::key()])]);
        $result     = $this->refreshDue();
        $row        = $this->row($connection);

        $expected = $refreshed ? [RefreshOutcome::REFRESHED, null] : [RefreshOutcome::FAILED, FailureReason::DISCOVERY_INVALID];

        self::assertSame($expected, [$result->outcome, $result->reason]);
        self::assertSame($refreshed ? [1, 1, 0] : [0, 0, 1], [$row->metadata_version, $row->jwks_version, $row->metadata_refresh_failures]);
        self::assertEquals(self::settings(['fetch_userinfo' => $fetches]), $row->settings);
    }

    /**
     * Rows of `[seconds the fetch takes, stale limit, refreshed]`: the limit by
     * the commit, from the document's validated moment.
     *
     * @return iterable<string, array{0: int, 1: int, 2: bool}>
     */
    public static function provideStaleLimits(): iterable
    {
        yield from [
            'a second under the limit' => [2591999, 2592000, true],
            'at the limit'             => [2592000, 2592000, false],
            'a second over the limit'  => [2592001, 2592000, false],
            'no limit'                 => [31536000, 0, true],
        ];
    }

    /**
     * What has passed its stale limit by the commit is `metadata_expired`,
     * which keeps the last good settings and keys; each resource's validated
     * fetch is stamped as its own.
     *
     * @param  int  $seconds
     * @param  int  $limit
     * @param  bool  $refreshed
     * @return void
     */
    #[DataProvider('provideStaleLimits')]
    public function testTheStaleLimitIsCheckedAtCommit(int $seconds, int $limit, bool $refreshed): void
    {
        config()->set('sso.metadata.stale_limit_seconds', $limit);

        $clock = $this->clock;

        $this->provider->respond('jwks', function (FetchRequest $request) use ($clock, $seconds): FetchResult {
            unset($request);

            $clock->advance($seconds);

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });

        $connection = $this->oidc([], ['jwks' => self::stored([self::next()])]);
        $result     = $this->refreshDue();
        $row        = $this->row($connection);

        self::assertSame($refreshed ? [RefreshOutcome::REFRESHED, null] : [RefreshOutcome::FAILED, FailureReason::METADATA_EXPIRED], [$result->outcome, $result->reason]);
        self::assertSame($refreshed ? self::NOW : null, $row->metadata_fetched_at?->toIso8601String());
        self::assertSame($refreshed ? $this->clock->now()->toIso8601String() : null, $row->jwks_fetched_at?->toIso8601String());
        self::assertSame($refreshed ? self::stored([self::key()]) : self::stored([self::next()]), $row->jwks);
    }

    /**
     * Rows of `[endpoint, response, reason]`: a refresh whose fetch brings no
     * `2xx` response, or a JWKS refused.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Sso\Fetching\FetchResult, 2: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideRefreshFailures(): iterable
    {
        $jwk = (string) json_encode(self::key()->jwk());

        yield from [
            'a discovery fetch refused' => ['discovery', FetchResult::refused(), FailureReason::FETCH_REFUSED],
            'a discovery fetch failed'  => ['discovery', FetchResult::failed(), FailureReason::FETCH_FAILED],
            'a discovery server error'  => ['discovery', FetchResult::fetched(500, [], '{}'), FailureReason::FETCH_FAILED],
            'a document refused'        => ['discovery', FetchResult::fetched(200, [], '[]'), FailureReason::DISCOVERY_INVALID],
            'a JWKS fetch refused'      => ['jwks', FetchResult::refused(), FailureReason::FETCH_REFUSED],
            'a JWKS fetch failed'       => ['jwks', FetchResult::failed(), FailureReason::FETCH_FAILED],
            'a JWKS server error'       => ['jwks', FetchResult::fetched(503, [], '{}'), FailureReason::FETCH_FAILED],
            'a JWKS refused'            => ['jwks', FetchResult::fetched(200, [], '{"keys":[]}'), FailureReason::JWKS_INVALID],
            'a JWKS with a key twice'   => ['jwks', FetchResult::fetched(200, [], '{"keys":[' . $jwk . ',' . $jwk . ']}'), FailureReason::JWKS_INVALID],
            'a JWKS repeating a member' => ['jwks', FetchResult::fetched(200, [], '{"keys":[],"keys":[' . $jwk . ']}'), FailureReason::JWKS_INVALID],
            'a JWKS keys an object'     => ['jwks', FetchResult::fetched(200, [], '{"keys":{"0":' . $jwk . '}}'), FailureReason::JWKS_INVALID],
        ];
    }

    /**
     * A failure raises the failures in a row, backs off and releases the claim,
     * keeping the last good settings and keys.
     *
     * @param  string  $endpoint
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $response
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefreshFailures')]
    public function testAFailureKeepsTheLastGoodSettingsAndKeys(string $endpoint, FetchResult $response, FailureReason $reason): void
    {
        $this->provider->respond($endpoint, $response);

        $connection = $this->oidc([], ['jwks' => self::stored([self::next()]), 'metadata_fetched_at' => $this->clock->now()->subDay()]);
        $result     = $this->refreshDue();
        $row        = $this->row($connection);

        self::assertSame([RefreshOutcome::FAILED, $reason, 1, self::BACKOFF], [$result->outcome, $result->reason, $result->failures, $result->nextAttemptAt?->toIso8601String()]);
        self::assertSame([1, self::BACKOFF], [$row->metadata_refresh_failures, $row->metadata_refresh_at?->toIso8601String()]);
        self::assertSame([null, null], [$row->metadata_claimed_until, $row->metadata_claim_token]);
        self::assertSame([0, 0, 0, null, self::stored([self::next()])], [$row->metadata_version, $row->jwks_version, $row->trust_version, $row->jwks_fetched_at, $row->jwks]);
        self::assertEquals(self::settings(), $row->settings);
    }

    /**
     * Rows of `[columns, settings]`: what changes while the refresh fetches,
     * each a conflict.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>}>
     */
    public static function provideConflicts(): iterable
    {
        yield from [
            'the trust version raised'  => [['trust_version' => 1], []],
            'the JWKS version raised'   => [['jwks_version' => 1], []],
            'another refresh wrote'     => [['metadata_version' => 1], []],
            'the claim taken over'      => [['metadata_claim_token' => str_repeat('f', 32)], []],
            'the claim released'        => [['metadata_claim_token' => null], []],
            'the issuer changed'        => [[], ['issuer' => 'https://other.example.test']],
            'the authorisation moved'   => [[], ['authorization_endpoint' => self::MOVED]],
            'the token endpoint moved'  => [[], ['token_endpoint' => self::MOVED]],
            'the JWKS URI moved'        => [[], ['jwks_uri' => self::MOVED]],
            'the UserInfo endpoint set' => [[], ['userinfo_endpoint' => self::MOVED]],
            'iss turned off'            => [[], ['returns_iss' => false]],
            'the algorithms changed'    => [[], ['id_token_algorithms' => ['RS256', 'PS256']]],
            'UserInfo turned on'        => [[], ['fetch_userinfo' => true]],
        ];
    }

    /**
     * A refresh that lost to a change made while it fetched is `conflict` and
     * writes nothing, on what it fetched or on a failure.
     *
     * @param  array<string, mixed>  $columns
     * @param  array<string, mixed>  $settings
     * @return void
     */
    #[DataProvider('provideConflicts')]
    public function testAChangeMadeWhileItFetchedIsAConflict(array $columns, array $settings): void
    {
        foreach ([FakeTokenEndpoint::json(200, $this->provider->jwks()), FetchResult::failed()] as $response) {

            $connection = $this->oidc([], ['jwks' => self::stored([self::next()])]);

            $this->changingWhileFetching($connection, $columns, $settings, $response);

            $result = $this->refreshDue();
            $row    = $this->row($connection);

            self::assertSame([RefreshOutcome::CONFLICT, FailureReason::METADATA_CONFLICT], [$result->outcome, $result->reason]);
            self::assertSame(self::stored([self::next()]), $row->jwks);
            self::assertSame([0, null, null, null], [$row->metadata_refresh_failures, $row->metadata_fetched_at, $row->jwks_fetched_at, $row->metadata_refresh_at]);
            self::assertEquals(self::settings($settings), $row->settings);

            // Out of the next round's way, whatever the change left of it
            $row->forceFill(['metadata_refresh_at' => $this->clock->now()->addYear()])->save();
        }
    }

    /**
     * A change of a setting a refresh neither depends on nor changes is no
     * conflict, and stands.
     *
     * @return void
     */
    public function testAChangeOfAnotherSettingStands(): void
    {
        $connection = $this->oidc([], ['jwks' => self::stored([self::key()])]);

        $this->changingWhileFetching($connection, [], ['scopes' => ['openid', 'groups']], FakeTokenEndpoint::json(200, $this->provider->jwks()));

        $result = $this->refreshDue();

        self::assertSame(RefreshOutcome::REFRESHED, $result->outcome);
        self::assertEquals(self::settings(['scopes' => ['openid', 'groups']]), $this->row($connection)->settings);
    }

    /**
     * An administrator's refresh comes unchanged from the shared machinery: for
     * the tenant's connection, skipping the backoff, never a claim, rate
     * limited, and refused for a connection that does not refresh.
     *
     * @return void
     */
    public function testAnAdministratorsRefreshComesFromTheSharedMachinery(): void
    {
        config()->set('sso.rate_limits.metadata.per_connection', ['max' => 2, 'decay_seconds' => 3600]);

        $actor      = new Caller(new IdentityReference('App\Models\User', '42'));
        $connection = $this->oidc([], ['metadata_refresh_at' => $this->clock->now()->addHour()]);
        $claimed    = $this->oidc([], ['metadata_claimed_until' => $this->clock->now()->addMinute()]);
        $off        = $this->oidc(['metadata_refresh' => false]);

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        self::assertSame(RefreshOutcome::REFRESHED, $this->refresher()->refreshNow(self::TENANT, $connection->id, $actor, Clients::browser())->outcome);
        self::assertSame(RefreshOutcome::IN_PROGRESS, $this->refresher()->refreshNow(self::TENANT, $claimed->id, $actor, Clients::browser())->outcome);
        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $this->refresher()->refreshNow('tenant-2', $connection->id, $actor, Clients::browser())->reason);
        self::assertSame(RefreshOutcome::REFRESHED, $this->refresher()->refreshNow(self::TENANT, $off->id, $actor, Clients::browser())->outcome);

        $this->refresher()->refreshNow(self::TENANT, $connection->id, $actor, Clients::browser());

        $limited = $this->refresher()->refreshNow(self::TENANT, $connection->id, $actor, Clients::browser());

        self::assertSame([RefreshOutcome::RATE_LIMITED, 1800], [$limited->outcome, $limited->retryAfter]);
    }

    /**
     * A stale administrator cannot refresh a connection whose switch is off:
     * its document or keys stay as they were, nothing is fetched, and the same
     * caller on a connection the schedule refreshes is no refusal.
     *
     * @return void
     */
    public function testAStaleAdministratorCannotOverwriteASwitchedOffConnection(): void
    {
        $actor = new Caller(new IdentityReference('App\Models\User', '42'));
        $moved = ['token_endpoint' => self::MOVED];
        $off   = $this->oidc(['metadata_refresh' => false, ...$moved], ['metadata_fetched_at' => $this->clock->now()->subDay()]);
        $on    = $this->oidc($moved);

        $this->app?->instance(Freshness::class, FakeFreshness::stale());

        $refused = $this->refresher()->refreshNow(self::TENANT, $off->id, $actor, Clients::browser());

        self::assertSame([RefreshOutcome::REFUSED, FailureReason::FRESHNESS_REQUIRED, $off->id], [$refused->outcome, $refused->reason, $refused->connectionId]);
        self::assertSame(self::MOVED, $this->row($off)->settings['token_endpoint']);
        self::assertSame(0, $this->row($off)->trust_version);

        $this->fetcher->assertNothingFetched();

        self::assertSame(RefreshOutcome::REFRESHED, $this->refresher()->refreshNow(self::TENANT, $on->id, $actor, Clients::browser())->outcome);
        self::assertSame(self::ISSUER . '/token', $this->row($on)->settings['token_endpoint']);
    }

    /**
     * With its switch off and no document ever fetched, a connection whose
     * endpoints were saved by hand refreshes its keys alone: nothing asks for
     * the document, an endpoint saved by hand stays, the keys are stamped and
     * when the document was validated stays unset.
     *
     * @return void
     */
    public function testAConnectionSavedByHandRefreshesItsKeysAlone(): void
    {
        $this->provider->publish(self::next());

        $stored     = ['jwks' => self::stored([self::key()]), 'jwks_fetched_at' => $this->clock->now()->subDays(29)];
        $connection = $this->oidc(['metadata_refresh' => false, 'token_endpoint' => self::MOVED], $stored);

        $result = $this->refreshDue();
        $row    = $this->row($connection);

        self::assertSame([RefreshOutcome::REFRESHED, [OidcMetadataSource::KEYS], false], [$result->outcome, $result->changedSettings, $result->trustChanged]);
        self::assertSame(1, $result->metadataVersion);
        self::assertSame(self::MOVED, $row->settings['token_endpoint']);
        self::assertSame(self::stored([self::key(), self::next()]), $row->jwks);
        self::assertSame([1, 0, self::NOW], [$row->jwks_version, $row->trust_version, $row->jwks_fetched_at?->toIso8601String()]);
        self::assertSame([null, null, self::TOMORROW], [$row->metadata_fetched_at, $row->metadata_valid_until, $row->metadata_refresh_at?->toIso8601String()]);
        self::assertSame([1, 0], [$row->metadata_version, $row->metadata_refresh_failures]);
        self::assertSame([null, null], [$row->metadata_claimed_until, $row->metadata_claim_token]);
        self::assertSame([FetchPurpose::JWKS], array_map(static fn (FetchRequest $request): FetchPurpose => $request->purpose, $this->fetcher->requests()));
    }

    /**
     * Rows of `[switch]`: a connection saved by hand at a provider that serves
     * no discovery document.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideNoDocumentSwitches(): iterable
    {
        yield 'its switch off' => [false];
        yield 'its switch on' => [true];
    }

    /**
     * An expired connection saved by hand, at a provider with no discovery
     * document, recovers by an administrator's refresh, its endpoints
     * unchanged: with its switch on the document's failure falls back to the
     * saved JWKS.
     *
     * @param  bool  $switch
     * @return void
     */
    #[DataProvider('provideNoDocumentSwitches')]
    public function testAnExpiredConnectionWithNoDiscoveryDocumentRecovers(bool $switch): void
    {
        $this->provider->respond('discovery', FetchResult::fetched(404, [], ''));

        $stored     = ['jwks' => self::stored([self::key()]), 'jwks_fetched_at' => $this->clock->now()->subDays(30)];
        $connection = $this->oidc(['metadata_refresh' => $switch, 'token_endpoint' => self::MOVED], $stored);
        $expiry     = app(MetadataExpiry::class);

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        self::assertTrue($expiry->isExpired($this->row($connection)));

        $result = $this->refresher()->refreshNow(self::TENANT, $connection->id, new Caller(new IdentityReference('App\Models\User', '42')), Clients::browser());
        $row    = $this->row($connection);

        self::assertSame([RefreshOutcome::REFRESHED, [], false], [$result->outcome, $result->changedSettings, $result->trustChanged]);
        self::assertFalse($expiry->isExpired($row));
        self::assertSame(self::MOVED, $row->settings['token_endpoint']);
        self::assertNull($row->metadata_fetched_at);
        self::assertSame(self::NOW, $row->jwks_fetched_at?->toIso8601String());
        self::assertCount($switch ? 2 : 1, $this->fetcher->requests());
    }

    /**
     * A connection that has never validated a document, with its switch on,
     * still follows the document when one is served: what it does save by hand
     * is what the document replaces.
     *
     * @return void
     */
    public function testAServedDocumentStillOverwritesWithTheSwitchOn(): void
    {
        $connection = $this->oidc(['token_endpoint' => self::MOVED]);
        $result     = $this->refreshDue();
        $row        = $this->row($connection);

        self::assertSame([RefreshOutcome::REFRESHED, ['token_endpoint', OidcMetadataSource::KEYS], true], [$result->outcome, $result->changedSettings, $result->trustChanged]);
        self::assertSame(self::ISSUER . '/token', $row->settings['token_endpoint']);
        self::assertSame(self::NOW, $row->metadata_fetched_at?->toIso8601String());
    }

    /**
     * A connection a document was validated for does not fall back: its
     * document must come back, or it would expire however fresh its keys are.
     *
     * @return void
     */
    public function testAConnectionWithAFetchedDocumentDoesNotFallBack(): void
    {
        $this->provider->respond('discovery', FetchResult::fetched(404, [], ''));

        $connection = $this->oidc([], ['metadata_fetched_at' => $this->clock->now()->subDay()]);
        $result     = $this->refreshDue();

        self::assertSame([RefreshOutcome::FAILED, FailureReason::FETCH_FAILED], [$result->outcome, $result->reason]);
        self::assertNull($this->row($connection)->jwks_fetched_at);
        self::assertSame([FetchPurpose::DISCOVERY], array_map(static fn (FetchRequest $request): FetchPurpose => $request->purpose, $this->fetcher->requests()));
    }

    /**
     * Both failing is the document's failure, recorded and backed off, the last
     * good keys kept; the switch off, there is only the JWKS's.
     *
     * @return void
     */
    public function testAFallbackThatFailsIsTheDocumentsFailure(): void
    {
        $this->provider->respond('discovery', FetchResult::fetched(200, [], '[]'));
        $this->provider->respond('jwks', FetchResult::failed());

        $on  = $this->oidc([], ['jwks' => self::stored([self::key()])]);
        $off = $this->oidc(['metadata_refresh' => false], ['jwks' => self::stored([self::key()]), 'jwks_fetched_at' => $this->clock->now()]);

        $first  = $this->refresher()->refreshQueued($on->id, Clients::browser());
        $second = $this->refresher()->refreshQueued($off->id, Clients::browser());

        self::assertSame([RefreshOutcome::FAILED, FailureReason::DISCOVERY_INVALID, 1], [$first->outcome, $first->reason, $first->failures]);
        self::assertSame([RefreshOutcome::FAILED, FailureReason::FETCH_FAILED, 1], [$second->outcome, $second->reason, $second->failures]);
        self::assertSame([0, self::stored([self::key()]), null], [$this->row($on)->jwks_version, $this->row($on)->jwks, $this->row($on)->jwks_fetched_at]);
        self::assertSame(self::BACKOFF, $this->row($off)->metadata_refresh_at?->toIso8601String());
    }

    /**
     * A refresh of keys alone that removes one voids what is in flight and
     * raises the trust version once, under the same rules as a whole refresh.
     *
     * @return void
     */
    public function testAKeysAloneRefreshThatRemovesAKeyVoids(): void
    {
        $connection = $this->oidc(['metadata_refresh' => false], ['jwks' => self::stored([self::key(), self::next()]), 'jwks_fetched_at' => $this->clock->now()]);
        $request    = $this->makeAuthorizationRequest($connection);
        $result     = $this->refreshDue();

        self::assertSame([RefreshOutcome::REFRESHED, [OidcMetadataSource::KEYS], true], [$result->outcome, $result->changedSettings, $result->trustChanged]);
        self::assertSame(1, $this->row($connection)->trust_version);
        self::assertSame(self::stored([self::key()]), $this->row($connection)->jwks);
        self::assertSame(self::NOW, $request->fresh()?->voided_at?->toIso8601String());
    }

    /**
     * A refresh of keys alone that changes nothing names nothing, voids nothing
     * and still renews the keys.
     *
     * @return void
     */
    public function testAKeysAloneRefreshThatChangesNothingRenewsThem(): void
    {
        $connection = $this->oidc(['metadata_refresh' => false], ['jwks' => self::stored([self::key()]), 'jwks_fetched_at' => $this->clock->now()->subDay()]);
        $request    = $this->makeAuthorizationRequest($connection);
        $result     = $this->refreshDue();

        self::assertSame([RefreshOutcome::REFRESHED, [], false], [$result->outcome, $result->changedSettings, $result->trustChanged]);
        self::assertSame(self::NOW, $this->row($connection)->jwks_fetched_at?->toIso8601String());
        self::assertNull($request->fresh()?->voided_at);
    }

    /**
     * Rows of `[seconds the commit takes, limit, refreshed]`: a refresh of keys
     * alone is judged at commit, by the moment they were validated.
     *
     * @return iterable<string, array{0: int, 1: int, 2: bool}>
     */
    public static function provideKeysAloneStaleLimits(): iterable
    {
        yield 'a second under' => [86399, 86400, true];
        yield 'at the limit' => [86400, 86400, false];
        yield 'no limit' => [90 * 86400, 0, true];
    }

    /**
     * A refresh of keys alone whose stale limit has passed by commit writes
     * nothing but the failure, the last good keys kept.
     *
     * @param  int  $seconds
     * @param  int  $limit
     * @param  bool  $refreshed
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideKeysAloneStaleLimits')]
    public function testAKeysAloneRefreshIsCheckedAtCommit(int $seconds, int $limit, bool $refreshed): void
    {
        config()->set('sso.metadata.stale_limit_seconds', $limit);

        $connection = $this->oidc(['metadata_refresh' => false], ['jwks' => self::stored([self::next()]), 'jwks_fetched_at' => $this->clock->now()]);
        $claim      = $this->source()->claim($this->row($connection));

        self::assertNotNull($claim);

        $fetched = $this->source()->fetch($claim);

        $this->clock->advance($seconds);

        $result = $this->source()->write($claim, $fetched, null, Clients::browser());
        $row    = $this->row($connection);

        self::assertSame($refreshed ? [RefreshOutcome::REFRESHED, null] : [RefreshOutcome::FAILED, FailureReason::METADATA_EXPIRED], [$result->outcome, $result->reason]);
        self::assertSame($refreshed ? [1, 1, 0] : [0, 0, 1], [$row->jwks_version, $row->trust_version, $row->metadata_refresh_failures]);
        self::assertSame(self::stored([$refreshed ? self::key() : self::next()]), $row->jwks);
    }

    /**
     * A change of the saved JWKS URL while a refresh of keys alone fetched is a
     * conflict: nothing is written for a URL no longer saved.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAKeysAloneRefreshLosesToAMovedUrl(): void
    {
        $connection = $this->oidc(['metadata_refresh' => false], ['jwks' => self::stored([self::next()]), 'jwks_fetched_at' => $this->clock->now()]);
        $claim      = $this->source()->claim($this->row($connection));

        self::assertNotNull($claim);

        $fetched = $this->source()->fetch($claim);

        Connection::query()->whereKey($connection->id)->update(['settings' => self::settings(['metadata_refresh' => false, 'jwks_uri' => self::MOVED])]);

        self::assertSame(RefreshOutcome::CONFLICT, $this->source()->write($claim, $fetched, null, Clients::browser())->outcome);
        self::assertSame([0, self::stored([self::next()])], [$this->row($connection)->jwks_version, $this->row($connection)->jwks]);
    }

    /**
     * With OIDC switched off nothing of it refreshes: it is not due, a queued
     * job skips it and an administrator is refused, with nothing fetched.
     *
     * @return void
     */
    public function testNothingRefreshesWithOidcOff(): void
    {
        $connection = $this->oidc();

        config()->set('sso.features.oidc', false);
        config()->set('sso.features.saml2', true);

        self::assertSame([], $this->refresher()->dueConnectionIds());
        self::assertSame([], $this->refresher()->refreshDue(Clients::browser()));
        self::assertSame(RefreshOutcome::SKIPPED, $this->refresher()->refreshQueued($connection->id, Clients::browser())->outcome);
        self::assertSame(
            FailureReason::FEATURE_DISABLED,
            $this->refresher()->refreshNow(self::TENANT, $connection->id, new Caller(new IdentityReference('App\Models\User', '42')), Clients::browser())->reason,
        );

        $this->fetcher->assertNothingFetched();
    }

    /**
     * Keys a refetch stamped on a connection whose refresh is on but has never
     * succeeded age out: the driver refuses it `metadata_expired` before any
     * request, until a refresh succeeds.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAFirstRefreshRecoversKeysPastTheirLimit(): void
    {
        $connection = $this->oidc([], ['jwks' => self::stored([self::key()]), 'jwks_fetched_at' => $this->clock->now()->subDays(30)]);
        $start      = fn (): ?FailureReason => app(OidcDriver::class)->start($this->row($connection), new StartRequest(
            Purpose::SIGN_IN,
            'web',
            RequestReference::fromString('Sq8tVv3w0kLmNoPqRsTuVwXyZ0123456'),
            new Secret('state'),
        ))->reason;

        self::assertSame(FailureReason::METADATA_EXPIRED, $start());
        self::assertSame(RefreshOutcome::REFRESHED, $this->refreshDue()->outcome);
        self::assertFalse(app(MetadataExpiry::class)->isExpired($this->row($connection)));
        self::assertSame(self::NOW, $this->row($connection)->jwks_fetched_at?->toIso8601String());
    }

    /**
     * A refresh that moved a setting reports the settings it moved, and a key
     * alone is not one.
     *
     * @return void
     */
    public function testARefreshReportsTheSettingsItMoved(): void
    {
        $this->oidc(['returns_iss' => false], ['jwks' => self::stored([self::key(), self::next()])]);
        $this->startRecordingEvents();

        $this->refreshDue();

        $updates = array_values(array_filter($this->recordedEvents(), static fn (object $event): bool => $event instanceof ConnectionUpdated));

        self::assertCount(1, $updates);
        self::assertSame(['returns_iss'], $updates[0]->changedSettings);
    }

    /**
     * A write of what is not an OIDC document records the failure, as a read
     * that brought nothing does.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAWriteOfAnotherDocumentRecordsAFailure(): void
    {
        $connection = $this->row($this->oidc([], ['jwks' => self::stored([self::key()])]));
        $claim      = $this->source()->claim($connection);

        self::assertInstanceOf(RefreshClaim::class, $claim);

        $result = $this->source()->write($claim, FetchedMetadata::read(new \stdClass, $this->clock->now()), null, Clients::browser());

        self::assertSame([RefreshOutcome::FAILED, FailureReason::DISCOVERY_INVALID], [$result->outcome, $result->reason]);
    }

    /**
     * Change the connection while the document is fetched, then have the JWKS
     * answer as given.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  array<string, mixed>  $columns
     * @param  array<string, mixed>  $settings
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $response
     * @return void
     */
    private function changingWhileFetching(Connection $connection, array $columns, array $settings, FetchResult $response): void
    {
        $this->provider->respond('jwks', function (FetchRequest $request) use ($connection, $columns, $settings, $response): FetchResult {
            unset($request);

            $row = $this->row($connection);

            $row->forceFill([...$columns, 'settings' => [...$row->settings, ...$settings]])->save();

            return $response;
        });
    }

    /**
     * The result of the one connection due.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     */
    private function refreshDue(): RefreshResult
    {
        $results = $this->refresher()->refreshDue(Clients::browser());

        self::assertCount(1, $results);

        return $results[0];
    }

    /**
     * A refreshing connection of the tenant holding the settings given, `null`
     * removing one.
     *
     * @param  array<string, mixed>  $settings
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function oidc(array $settings = [], array $attributes = []): Connection
    {
        return $this->makeConnection(['settings' => self::settings($settings), ...$attributes]);
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
     * The source, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\OidcMetadataSource
     */
    private function source(): OidcMetadataSource
    {
        return app(OidcMetadataSource::class);
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
     * The settings of a refreshing connection that matches the provider's
     * document, with the changes laid over them, `null` removing one.
     *
     * @param  array<string, mixed>  $changes
     * @return array<string, mixed>
     */
    private static function settings(array $changes = []): array
    {
        $stored = OidcSettings::fromArray([
            'issuer'                 => self::ISSUER,
            'authorization_endpoint' => self::ISSUER . '/authorize',
            'token_endpoint'         => self::ISSUER . '/token',
            'jwks_uri'               => self::ISSUER . '/jwks',
            'userinfo_endpoint'      => self::ISSUER . '/userinfo',
            'returns_iss'            => true,
            'client_id'              => FakeOpenIdProvider::CLIENT_ID,
            'metadata_refresh'       => true,
        ])->toArray();

        return array_filter([...$stored, ...$changes], static fn (mixed $value): bool => $value !== null);
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

        return ProviderKeySet::read($jwks, AlgorithmAllowList::of(['RS256']), 65536, 50)?->toStored() ?? '';
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
