<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Connections\ImportSaver;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Metadata\DiscoveryImporter;
use SineMacula\Laravel\Sso\Metadata\MetadataExpiry;
use SineMacula\Laravel\Sso\Metadata\MetadataImporter;
use SineMacula\Laravel\Sso\Metadata\ProposedOidcSettings;
use SineMacula\Laravel\Sso\Metadata\ProposedSettings;
use SineMacula\Laravel\Sso\Metadata\ValidatedFetch;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for saving a fetched import (SSO-2.8, SSO-2.11): the stale
 * limit counts from the fetch a proposal came from, whether or not a refresh
 * has run, so an imported connection with its schedule off never has unlimited
 * trust, but for a SAML connection that has not opted in, which starts no clock;
 * metadata given as XML, from no fetch, is saved as by hand; a save that
 * changed nothing still stamps, on the record, voiding nothing; and a refusal
 * stamps nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportSaver::class)]
#[CoversClass(ValidatedFetch::class)]
#[CoversClass(ProposedSettings::class)]
#[CoversClass(ProposedOidcSettings::class)]
final class ImportSaverTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The tenant whose connection saves. */
    private const string TENANT = 'tenant-1';

    /** @var string The URL the provider serves its metadata at. */
    private const string URL = 'https://idp.example.test/metadata.xml';

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T09:30:00+00:00';

    /** @var string The stale limit past when each test starts. */
    private const string LIMIT = '2026-12-01T09:30:00+00:00';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The SAML provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The OpenID provider's key, generated once. */
    private static ?FakeSigningKey $key = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher an import fetches through. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFreshness The freshness contract the save asks. */
    private FakeFreshness $freshness;

    /**
     * Bind a fixed clock, a fake fetcher and a fresh freshness contract, switch
     * both protocols on and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock     = new FixedClock(self::NOW);
        $this->fetcher   = new FakeFetcher;
        $this->freshness = FakeFreshness::fresh();

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Fetcher::class, $this->fetcher);
        $this->app?->instance(Freshness::class, $this->freshness);

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://api.example.com');

        $this->usePackageTables();
    }

    /**
     * An import from a URL, saved to an anchored connection with its schedule
     * off, counts from its fetch, and its `validUntil` is enforced.
     *
     * @return void
     */
    public function testAFetchedSamlImportCountsFromItsFetch(): void
    {
        $connection = $this->saml(['metadata_url' => self::URL, 'metadata_refresh' => false]);
        $proposed   = $this->samlProposal(CarbonImmutable::parse('2026-11-10T00:00:00Z'));
        $fetch      = $proposed->fetch();

        $this->anchor($connection);

        self::assertNotNull($fetch);
        self::assertSame([self::NOW, '2026-11-10T00:00:00+00:00'], [$fetch->validatedAt->toIso8601String(), $fetch->validUntil?->toIso8601String()]);

        $result = $this->saver()->save(self::TENANT, $connection->id, ['settings' => $proposed->settings()], $fetch, Clients::browser());
        $row    = $this->row($connection);

        self::assertTrue($result->isChanged());
        self::assertSame(self::NOW, $row->metadata_fetched_at?->toIso8601String());
        self::assertSame('2026-11-10T00:00:00+00:00', $row->metadata_valid_until?->toIso8601String());
        self::assertSame('2026-11-10T00:00:00+00:00', app(MetadataExpiry::class)->expiresAt($row)?->toIso8601String());

        $this->clock->advance(9 * 86400);

        self::assertTrue(app(MetadataExpiry::class)->isExpired($this->row($connection)));
    }

    /**
     * Rows of `[anchored, settings, stamped, expiry]`: what saving an import
     * stamps on a SAML connection, and when that connection then expires.
     *
     * @return iterable<string, array{0: bool, 1: array<string, mixed>, 2: bool, 3: ?string}>
     */
    public static function provideSamlImports(): iterable
    {
        $url = ['metadata_url' => self::URL];

        yield from [
            'an anchor, unset'         => [true, $url, true, self::LIMIT],
            'an anchor, true'          => [true, [...$url, 'metadata_refresh' => true], true, self::LIMIT],
            'an anchor, false'         => [true, [...$url, 'metadata_refresh' => false], true, self::LIMIT],
            'no anchor, unset'         => [false, $url, false, null],
            'no anchor, true'          => [false, [...$url, 'metadata_refresh' => true], true, self::LIMIT],
            'no anchor, false'         => [false, [...$url, 'metadata_refresh' => false], false, null],
            'no anchor, no URL'        => [false, [], false, null],
            'an anchor, unset, no URL' => [true, [], false, null],
        ];
    }

    /**
     * A reviewed import starts a clock only where the connection holds a
     * deadline: one that will not refresh, its certificates as good as entered
     * by hand, never expires for having been imported.
     *
     * @param  bool  $anchored
     * @param  array<string, mixed>  $settings
     * @param  bool  $stamped
     * @param  ?string  $expiry
     * @return void
     */
    #[DataProvider('provideSamlImports')]
    public function testASamlImportStartsAClockOnlyWhereItHoldsADeadline(bool $anchored, array $settings, bool $stamped, ?string $expiry): void
    {
        $connection = $this->saml($settings);
        $proposed   = $this->samlProposal(CarbonImmutable::parse('2027-01-01T00:00:00Z'));

        if ($anchored) {
            $this->anchor($connection);
        }

        $result = $this->saver()->save(self::TENANT, $connection->id, ['settings' => $proposed->settings()], $this->fetchOf($proposed), Clients::browser());
        $row    = $this->row($connection);

        self::assertTrue($result->isChanged());
        self::assertSame($stamped ? self::NOW : null, $row->metadata_fetched_at?->toIso8601String());
        self::assertSame($stamped ? '2027-01-01T00:00:00+00:00' : null, $row->metadata_valid_until?->toIso8601String());
        self::assertSame($expiry, app(MetadataExpiry::class)->expiresAt($row)?->toIso8601String());

        $this->clock->advance(31 * 86400);

        self::assertSame($expiry !== null, app(MetadataExpiry::class)->isExpired($this->row($connection)));
    }

    /**
     * The save judges the connection as its own change leaves it: an import
     * that opts in stamps, and one that opts out starts no clock and clears the
     * one that was running.
     *
     * @return void
     */
    public function testASamlImportIsJudgedAfterItsChange(): void
    {
        $proposed = $this->samlProposal(CarbonImmutable::parse('2027-01-01T00:00:00Z'));
        $optedIn  = $this->saml(['metadata_url' => self::URL]);
        $optedOut = $this->saml(['metadata_url' => self::URL, 'metadata_refresh' => true], ['metadata_fetched_at' => $this->clock->now()->subDays(40)]);

        $this->saver()->save(self::TENANT, $optedIn->id, ['settings' => [...$proposed->settings(), 'metadata_refresh' => true]], $this->fetchOf($proposed), Clients::browser());
        $this->saver()->save(self::TENANT, $optedOut->id, ['settings' => [...$proposed->settings(), 'metadata_refresh' => null]], $this->fetchOf($proposed), Clients::browser());

        self::assertSame(self::NOW, $this->row($optedIn)->metadata_fetched_at?->toIso8601String());
        self::assertSame([null, null], [$this->row($optedOut)->metadata_fetched_at, $this->row($optedOut)->metadata_valid_until]);
        self::assertFalse(app(MetadataExpiry::class)->isExpired($this->row($optedOut)));
    }

    /**
     * A save that changed nothing on a connection that holds no deadline clears
     * a stamp left from before, on the record, and with none to clear it
     * reports nothing, since it did nothing.
     *
     * @return void
     */
    public function testAnUnchangedSamlSaveWithNoDeadlineReportsOnlyAClearedStamp(): void
    {
        $proposed = $this->samlProposal(CarbonImmutable::parse('2027-01-01T00:00:00Z'));
        $settings = ['metadata_url' => self::URL, ...$proposed->settings()];
        $stamped  = $this->saml($settings, ['metadata_fetched_at' => $this->clock->now()->subDays(40), 'metadata_valid_until' => $this->clock->now()->subDay()]);
        $clean    = $this->saml($settings);

        $this->startRecordingEvents();

        self::assertFalse($this->saver()->save(self::TENANT, $stamped->id, ['settings' => $proposed->settings()], $this->fetchOf($proposed), Clients::browser())->isChanged());

        $events = $this->recordedEvents();

        self::assertCount(1, $events);
        self::assertInstanceOf(ConnectionUpdated::class, $events[0]);
        self::assertSame(['metadata_fetched_at'], $events[0]->changedSettings);
        self::assertSame([null, null], [$this->row($stamped)->metadata_fetched_at, $this->row($stamped)->metadata_valid_until]);

        $this->startRecordingEvents();

        self::assertFalse($this->saver()->save(self::TENANT, $clean->id, ['settings' => $proposed->settings()], $this->fetchOf($proposed), Clients::browser())->isChanged());
        self::assertSame([], $this->recordedEvents());
        self::assertSame(0, $this->row($clean)->trust_version);
    }

    /**
     * Saving an import of the same settings renews an expired connection that
     * holds a deadline, on the record.
     *
     * @return void
     */
    public function testAnUnchangedSamlSaveWithADeadlineRenews(): void
    {
        $proposed   = $this->samlProposal(CarbonImmutable::parse('2027-01-01T00:00:00Z'));
        $connection = $this->saml(['metadata_url' => self::URL, 'metadata_refresh' => true, ...$proposed->settings()], ['metadata_fetched_at' => $this->clock->now()->subDays(40)]);

        self::assertTrue(app(MetadataExpiry::class)->isExpired($this->row($connection)));

        $this->startRecordingEvents();

        self::assertFalse($this->saver()->save(self::TENANT, $connection->id, ['settings' => $proposed->settings()], $this->fetchOf($proposed), Clients::browser())->isChanged());

        $events = $this->recordedEvents();

        self::assertCount(1, $events);
        self::assertInstanceOf(ConnectionUpdated::class, $events[0]);
        self::assertFalse(app(MetadataExpiry::class)->isExpired($this->row($connection)));
    }

    /**
     * A stale caller stamps nothing on a SAML connection and clears nothing.
     *
     * @return void
     */
    public function testAStaleCallerLeavesASamlConnectionAlone(): void
    {
        $proposed   = $this->samlProposal(CarbonImmutable::parse('2027-01-01T00:00:00Z'));
        $connection = $this->saml(['metadata_url' => self::URL], ['metadata_fetched_at' => $this->clock->now()->subDays(40)]);

        $this->app?->instance(Freshness::class, FakeFreshness::stale());

        $result = $this->saver()->save(self::TENANT, $connection->id, ['settings' => $proposed->settings()], $this->fetchOf($proposed), Clients::browser());

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertSame('2026-09-22T09:30:00+00:00', $this->row($connection)->metadata_fetched_at?->toIso8601String());
    }

    /**
     * Metadata given as XML came from no fetch, so its proposal has none.
     *
     * @return void
     */
    public function testAnXmlImportHasNoFetch(): void
    {
        $result = app(MetadataImporter::class)->importXml(self::TENANT, null, self::metadata()->toXml(), FakeSamlIdentityProvider::ENTITY_ID);

        self::assertTrue($result->isProposed());
        self::assertNull($result->proposed?->fetch());
    }

    /**
     * An OIDC import, saved with its schedule off, counts from the moment its
     * document validated, with no `validUntil`; its keys wait for their fetch.
     *
     * @return void
     */
    public function testAFetchedOidcImportCountsFromItsFetch(): void
    {
        $connection = $this->oidc(['metadata_refresh' => false]);
        $proposed   = $this->oidcProposal();

        self::assertSame(self::NOW, $proposed->fetch()->validatedAt->toIso8601String());
        self::assertNull($proposed->fetch()->validUntil);

        self::assertTrue($this->saver()->save(self::TENANT, $connection->id, ['settings' => $proposed->settings()], $proposed->fetch(), Clients::browser())->isSucceeded());

        $row = $this->row($connection);

        self::assertSame(self::NOW, $row->metadata_fetched_at?->toIso8601String());
        self::assertNull($row->jwks_fetched_at);
        self::assertSame(self::LIMIT, app(MetadataExpiry::class)->expiresAt($row)?->toIso8601String());
    }

    /**
     * A change of the issuer clears what was fetched for the one before, then
     * what the save was fetched for is stamped: the keys wait, the document
     * does not.
     *
     * @return void
     */
    public function testAnIssuerChangedByTheSaveIsStampedAfterItsReset(): void
    {
        $yesterday  = $this->clock->now()->subDay();
        $connection = $this->oidc(['issuer' => 'https://old.example.test'], ['jwks' => '{"keys":[]}', 'jwks_fetched_at' => $yesterday, 'metadata_fetched_at' => $yesterday]);
        $proposed   = $this->oidcProposal();

        self::assertTrue($this->saver()->save(self::TENANT, $connection->id, ['settings' => $proposed->settings()], $proposed->fetch(), Clients::browser())->isChanged());

        $row = $this->row($connection);

        self::assertSame([self::NOW, null, null], [$row->metadata_fetched_at?->toIso8601String(), $row->jwks_fetched_at, $row->jwks]);
    }

    /**
     * Saving a new import of the same settings recovers an expired connection
     * on the record: it stamps, voids nothing, and reports the one thing it
     * changed.
     *
     * @return void
     */
    public function testAnUnchangedSaveRenewsAndReportsIt(): void
    {
        $proposed   = $this->oidcProposal();
        $connection = $this->oidc($proposed->settings(), ['metadata_fetched_at' => $this->clock->now()->subDays(30)]);
        $request    = $this->makeAuthorizationRequest($connection);

        self::assertTrue(app(MetadataExpiry::class)->isExpired($this->row($connection)));

        $this->startRecordingEvents();

        $result = $this->saver()->save(
            self::TENANT,
            $connection->id,
            ['settings' => $proposed->settings()],
            $proposed->fetch(),
            Clients::browser(),
            new ActingIdentity('App\Models\User', '42'),
        );
        $row    = $this->row($connection);
        $events = $this->recordedEvents();

        self::assertTrue($result->isSucceeded());
        self::assertFalse($result->isChanged());
        self::assertFalse(app(MetadataExpiry::class)->isExpired($row));
        self::assertSame(0, $row->trust_version);
        self::assertNull($request->fresh()?->voided_at);
        self::assertCount(1, $events);
        self::assertInstanceOf(ConnectionUpdated::class, $events[0]);
        self::assertSame(['metadata_fetched_at'], $events[0]->changedSettings);
    }

    /**
     * A changed save reports the settings it changed, not the stamp, and voids
     * as any trust change does.
     *
     * @return void
     */
    public function testAChangedSaveReportsItsChangeAlone(): void
    {
        $proposed   = $this->oidcProposal();
        $connection = $this->oidc([...$proposed->settings(), 'token_endpoint' => 'https://moved.example.test/token']);
        $request    = $this->makeAuthorizationRequest($connection);

        $this->startRecordingEvents();

        self::assertSame(
            ['token_endpoint'],
            $this->saver()->save(self::TENANT, $connection->id, ['settings' => $proposed->settings()], $proposed->fetch(), Clients::browser())->changedSettings,
        );

        $events = $this->recordedEvents();

        self::assertCount(1, $events);
        self::assertInstanceOf(ConnectionUpdated::class, $events[0]);
        self::assertSame(['token_endpoint'], $events[0]->changedSettings);
        self::assertSame(1, $this->row($connection)->trust_version);
        self::assertSame(self::NOW, $request->fresh()?->voided_at?->toIso8601String());
    }

    /**
     * A stale caller is refused before anything is validated or written, even a
     * save that changes no setting, and the operation asked is the connection's
     * trust.
     *
     * @return void
     */
    public function testAStaleCallerStampsNothing(): void
    {
        $proposed   = $this->oidcProposal();
        $connection = $this->oidc($proposed->settings());

        $this->freshness = FakeFreshness::stale();
        $this->app?->instance(Freshness::class, $this->freshness);

        $result = $this->saver()->save(self::TENANT, $connection->id, ['settings' => $proposed->settings()], $proposed->fetch(), Clients::browser());

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertNull($this->row($connection)->metadata_fetched_at);
        self::assertSame([FreshnessOperation::CONNECTION_TRUST], array_column($this->freshness->asked(), 'operation'));
    }

    /**
     * A change the service refuses stamps nothing.
     *
     * @return void
     */
    public function testAnInvalidChangeStampsNothing(): void
    {
        $proposed   = $this->oidcProposal();
        $connection = $this->oidc();
        $result     = $this->saver()->save(self::TENANT, $connection->id, ['settings' => ['token_endpoint' => 'http://nope.example.test']], $proposed->fetch(), Clients::browser());

        self::assertTrue($result->isInvalid());
        self::assertNull($this->row($connection)->metadata_fetched_at);
    }

    /**
     * Another tenant's connection, an unknown one and a protocol switched off
     * are refused, with nothing asked or stamped.
     *
     * @return void
     */
    public function testAConnectionThatCannotBeSavedIsRefused(): void
    {
        $proposed   = $this->oidcProposal();
        $connection = $this->oidc();
        $fetch      = $proposed->fetch();
        $asked      = $this->freshness->asked();

        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $this->saver()->save('tenant-2', $connection->id, [], $fetch, Clients::browser())->reason);
        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $this->saver()->save(self::TENANT, '01jbunknownconnection00000', [], $fetch, Clients::browser())->reason);

        config()->set('sso.features.oidc', false);

        self::assertSame(FailureReason::PROTOCOL_UNAVAILABLE, $this->saver()->save(self::TENANT, $connection->id, [], $fetch, Clients::browser())->reason);
        self::assertSame($asked, $this->freshness->asked());
        self::assertNull($this->row($connection)->metadata_fetched_at);
    }

    /**
     * A proposal's own dump shows nothing of when it was fetched beyond what it
     * did, and it stays impossible to serialise.
     *
     * @return void
     */
    public function testAProposalKeepsItsDump(): void
    {
        $proposed = $this->oidcProposal();

        self::assertSame(['settings', 'auth_methods', 'keys'], array_keys($proposed->jsonSerialize()));
    }

    /**
     * What the provider's metadata proposes for the pinned entity, fetched from
     * the URL.
     *
     * @param  \Carbon\CarbonImmutable  $validUntil
     * @return \SineMacula\Laravel\Sso\Metadata\ProposedSettings
     */
    private function samlProposal(CarbonImmutable $validUntil): ProposedSettings
    {
        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], self::metadata()->with(['valid_until' => $validUntil])->toXml()));

        $result = app(MetadataImporter::class)->importUrl(self::TENANT, null, self::URL, FakeSamlIdentityProvider::ENTITY_ID);

        self::assertNotNull($result->proposed);

        return $result->proposed;
    }

    /**
     * What the OpenID provider's document proposes.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\ProposedOidcSettings
     */
    private function oidcProposal(): ProposedOidcSettings
    {
        (new FakeOpenIdProvider(FakeOpenIdProvider::ISSUER, self::key()))->serve($this->fetcher);

        $result = app(DiscoveryImporter::class)->import(self::TENANT, FakeOpenIdProvider::ISSUER);

        self::assertNotNull($result->proposed);

        return $result->proposed;
    }

    /**
     * The fetch a SAML proposal carries.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\ProposedSettings  $proposed
     * @return \SineMacula\Laravel\Sso\Metadata\ValidatedFetch
     */
    private function fetchOf(ProposedSettings $proposed): ValidatedFetch
    {
        $fetch = $proposed->fetch();

        self::assertNotNull($fetch);

        return $fetch;
    }

    /**
     * A SAML connection of the tenant, with the settings and attributes given.
     *
     * @param  array<string, mixed>  $settings
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(array $settings = [], array $attributes = []): Connection
    {
        return $this->makeConnection(['tenant_id' => self::TENANT, 'protocol' => 'saml2', 'settings' => Saml2Settings::fromArray($settings)->toArray(), ...$attributes]);
    }

    /**
     * Give the connection a metadata signing anchor.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     */
    private function anchor(Connection $connection): void
    {
        $masked = MaskedKey::fromCertificate(Certificates::distinct(0));

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::METADATA_SIGNING,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $masked->certificate,
            'public_key'    => $masked->publicKey,
            'fingerprint'   => $masked->fingerprint,
        ])->save();
    }

    /**
     * An OIDC connection of the tenant, with the settings and attributes given.
     *
     * @param  array<string, mixed>  $settings
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function oidc(array $settings = [], array $attributes = []): Connection
    {
        return $this->makeConnection([
            'tenant_id' => self::TENANT,
            'settings'  => OidcSettings::fromArray([
                'issuer'                 => FakeOpenIdProvider::ISSUER,
                'authorization_endpoint' => FakeOpenIdProvider::ISSUER . '/authorize',
                'token_endpoint'         => FakeOpenIdProvider::ISSUER . '/token',
                'jwks_uri'               => FakeOpenIdProvider::ISSUER . '/jwks',
                'client_id'              => FakeOpenIdProvider::CLIENT_ID,
                ...$settings,
            ])->toArray(),
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
     * The helper, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ImportSaver
     */
    private function saver(): ImportSaver
    {
        return app(ImportSaver::class);
    }

    /**
     * The provider's metadata.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata
     */
    private static function metadata(): FakeSamlMetadata
    {
        self::$idp ??= new FakeSamlIdentityProvider;

        return self::$idp->metadata(FakeSamlIdentityProvider::SSO_URL);
    }

    /**
     * The OpenID provider's key.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(): FakeSigningKey
    {
        return self::$key ??= FakeSigningKey::rsa('rsa-1');
    }
}
