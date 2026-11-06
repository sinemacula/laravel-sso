<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\SamlMetadata;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\ConnectionSummary;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\ImportSaver;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Keys\Enums\KeyStatus;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyResult;
use SineMacula\Laravel\Sso\Metadata\ImportResult;
use SineMacula\Laravel\Sso\Metadata\MetadataImporter;
use SineMacula\Laravel\Sso\Metadata\ProposedSettings;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Integration\Examples\Clients;

/**
 * The import, save and anchor examples of `docs/guides/saml-metadata.md`
 * (SSO-2.5, SSO-2.8, SSO-2.11, SSO-12.5), on the shared example harness, with
 * the application's own tenant: the import endpoint fetches the provider's
 * metadata and shows the administrator exactly the settings, certificates,
 * NameID formats and expiry the guide lists, writing nothing, for the tenant's
 * connection or before it exists; a URL that fails goes back with
 * `fetch_failed`, and an import past the connection's metadata limit goes back
 * with the wait. The save endpoint stores a fetched proposal through the import
 * saver and one given as XML as by hand, each asking for the connection's trust
 * and trusting the signing certificate, after which the connection is usable; a
 * stale caller goes back with `freshness_required` and nothing is trusted. A
 * metadata signing anchor then holds every import naming the connection to its
 * signature.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataImporter::class)]
#[CoversClass(ImportResult::class)]
#[CoversClass(ProposedSettings::class)]
#[CoversClass(ImportSaver::class)]
final class SamlMetadataImportExampleTest extends SamlMetadataExampleTestCase
{
    /** @var string When the provider's metadata says it expires. */
    private const string VALID_UNTIL = '2026-12-01T00:00:00Z';

    /**
     * Serve the provider's metadata from its URL, and make the tenant's bare
     * SAML connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->serve($this->idp->metadata(self::SSO_URL)->with(['valid_until' => CarbonImmutable::parse(self::VALID_UNTIL)])->toXml());
    }

    /**
     * The import fetches the metadata as a metadata request and proposes
     * exactly what the guide lists, writing nothing to the connection.
     *
     * @return void
     */
    public function testTheImportProposesWhatTheMetadataHolds(): void
    {
        $shown = $this->import($this->connection);

        self::assertIsArray($shown);
        self::assertEquals(['idp_entity_id' => self::ENTITY_ID, 'sso_url' => self::SSO_URL, 'sso_binding' => 'http_redirect'], $shown['settings']);
        self::assertIsArray($shown['signing']);
        self::assertCount(1, $shown['signing']);
        self::assertStringStartsWith('-----BEGIN CERTIFICATE-----', $shown['signing'][0]['certificate']);
        self::assertSame(openssl_x509_fingerprint($this->idp->certificate(), 'sha256'), $shown['signing'][0]['fingerprint']);
        self::assertSame([], $shown['encryption']);
        self::assertSame([FakeSamlResponse::PERSISTENT], $shown['formats']);
        self::assertInstanceOf(CarbonImmutable::class, $shown['valid_until']);
        self::assertSame(self::VALID_UNTIL, $shown['valid_until']->toIso8601ZuluString());

        $this->fetcher->assertFetched(self::METADATA_URL, FetchPurpose::METADATA);
        self::assertArrayNotHasKey('idp_entity_id', $this->stored()->settings);
        self::assertSame([], $this->trustedFingerprints(KeyUse::IDP_SIGNING));
    }

    /**
     * Before the connection exists, the import names none and proposes the same
     * settings.
     *
     * @return void
     */
    public function testAnImportBeforeTheConnectionExistsProposesToo(): void
    {
        $shown = $this->import(null);

        self::assertIsArray($shown);
        self::assertEquals(['idp_entity_id' => self::ENTITY_ID, 'sso_url' => self::SSO_URL, 'sso_binding' => 'http_redirect'], $shown['settings']);
    }

    /**
     * A metadata URL that does not answer `2xx` goes back with `fetch_failed`.
     *
     * @return void
     */
    public function testARefusedImportGoesBackWithItsReason(): void
    {
        $this->fetcher->respond(self::METADATA_URL, FetchResult::fetched(500, [], 'Internal Server Error'));

        self::assertSame(['metadata' => ['fetch_failed']], self::errors($this->import($this->connection)));
    }

    /**
     * An import past the connection's metadata limit goes back with the seconds
     * until its window ends, having fetched nothing.
     *
     * @return void
     */
    public function testAnImportPastTheLimitGoesBackWithTheWait(): void
    {
        config()->set('sso.rate_limits.metadata.per_connection', ['max' => 1, 'decay_seconds' => 3600]);

        self::assertIsArray($this->import($this->connection));
        self::assertCount(1, $this->fetcher->requests());

        self::assertSame(['metadata' => ['Try again in 1800 seconds.']], self::errors($this->import($this->connection)));
        self::assertCount(1, $this->fetcher->requests());
    }

    /**
     * A fetched proposal is saved through the import saver, asking for the
     * connection's trust, and its signing certificate trusted, after which the
     * connection, enabled, is usable.
     *
     * @return void
     */
    public function testSavingAFetchedProposalMakesTheConnectionUsable(): void
    {
        $proposed = $this->proposed();

        self::assertNotNull($proposed->fetch());

        $freshness = FakeFreshness::fresh();
        $this->instance(Freshness::class, $freshness);

        $saved = $this->save($proposed);

        self::assertInstanceOf(ConnectionResult::class, $saved);
        self::assertSame(ConnectionStatus::UPDATED, $saved->status);
        $freshness->assertAsked(FreshnessOperation::CONNECTION_TRUST);

        $this->assertSavedAndUsable();
    }

    /**
     * A proposal from metadata given as XML came from no fetch, so it is saved
     * as by hand, and the connection is usable all the same.
     *
     * @return void
     */
    public function testSavingAProposalGivenAsXmlUpdatesTheConnectionAsByHand(): void
    {
        $xml      = $this->idp->metadata(self::SSO_URL)->toXml();
        $proposed = app(MetadataImporter::class)->importXml(self::TENANT, $this->connection->id, $xml, self::ENTITY_ID)->proposed;

        self::assertNotNull($proposed);
        self::assertNull($proposed->fetch());

        $saved = $this->save($proposed);

        self::assertInstanceOf(ConnectionResult::class, $saved);
        self::assertSame(ConnectionStatus::UPDATED, $saved->status);
        $this->fetcher->assertNothingFetched();

        $this->assertSavedAndUsable();
    }

    /**
     * A caller who has not authenticated recently enough goes back with
     * `freshness_required`: nothing is saved and no certificate trusted.
     *
     * @return void
     */
    public function testAStaleCallerGoesBackAndNothingIsTrusted(): void
    {
        $proposed = $this->proposed();

        $this->freshness->staleFor(FreshnessOperation::CONNECTION_TRUST);

        self::assertSame(['metadata' => ['freshness_required']], self::errors($this->save($proposed)));
        self::assertArrayNotHasKey('idp_entity_id', $this->stored()->settings);
        self::assertSame([], $this->trustedFingerprints(KeyUse::IDP_SIGNING));
    }

    /**
     * Once the federation's certificate is trusted as the connection's metadata
     * signing anchor, asking for its trust, an import naming the connection is
     * refused unsigned or signed by any other key, and read when the anchor
     * signed it; an import naming no connection applies no anchor.
     *
     * @return void
     */
    public function testAnAnchorHoldsEveryImportNamingTheConnectionToItsSignature(): void
    {
        $federation = new FakeSamlIdentityProvider('https://federation.example.com');

        $freshness = FakeFreshness::fresh();
        $this->instance(Freshness::class, $freshness);

        $anchored = self::atEndpoint('anchor', [
            'tenant'     => $this->tenant,
            'connection' => $this->connection,
            'anchor'     => $federation->certificate(),
            'actor'      => self::actor(),
        ]);

        self::assertInstanceOf(KeyResult::class, $anchored);
        self::assertSame([KeyStatus::TRUSTED, KeyUse::METADATA_SIGNING], [$anchored->status, $anchored->key?->use]);
        self::assertSame([openssl_x509_fingerprint($federation->certificate(), 'sha256')], $this->trustedFingerprints(KeyUse::METADATA_SIGNING));
        $freshness->assertAsked(FreshnessOperation::CONNECTION_TRUST);

        $importer = app(MetadataImporter::class);
        $metadata = $this->idp->metadata(self::SSO_URL);
        $unsigned = $importer->importXml(self::TENANT, $this->connection->id, $metadata->toXml(), self::ENTITY_ID);
        $forged   = $importer->importXml(self::TENANT, $this->connection->id, $metadata->with(['sign' => 'entity'])->toXml(), self::ENTITY_ID);
        $signed   = $metadata->with(['sign' => 'entity'])->signedBy($federation->signer())->toXml();

        self::assertSame([FailureReason::METADATA_SIGNATURE_INVALID, 'unsigned'], [$unsigned->reason, $unsigned->detail]);
        self::assertSame([FailureReason::METADATA_SIGNATURE_INVALID, 'signature'], [$forged->reason, $forged->detail]);
        self::assertTrue($importer->importXml(self::TENANT, $this->connection->id, $signed, self::ENTITY_ID)->isProposed());
        self::assertTrue($importer->importXml(self::TENANT, null, $metadata->toXml(), self::ENTITY_ID)->isProposed());
    }

    /**
     * Make the tenant's bare SAML connection.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionSummary
     */
    #[\Override]
    protected function makeConnection(): ConnectionSummary
    {
        $created = app(ConnectionService::class)->create(self::TENANT, 'saml2', 'Acme SAML', Clients::browser());

        self::assertNotNull($created->connection);

        return $created->connection;
    }

    /**
     * The connection holds the proposed settings and trusts the provider's
     * certificate alone, and, enabled, is usable.
     *
     * @return void
     */
    private function assertSavedAndUsable(): void
    {
        $settings = $this->stored()->settings;

        self::assertSame([self::ENTITY_ID, self::SSO_URL, 'http_redirect'], [$settings['idp_entity_id'] ?? null, $settings['sso_url'] ?? null, $settings['sso_binding'] ?? null]);
        self::assertSame([openssl_x509_fingerprint($this->idp->certificate(), 'sha256')], $this->trustedFingerprints(KeyUse::IDP_SIGNING));
        self::assertTrue(app(ConnectionService::class)->enable(self::TENANT, $this->connection->id, Clients::browser())->isSucceeded());
        self::assertTrue($this->stored()->usable);
    }

    /**
     * Run the import endpoint for the connection, or none, and answer what it
     * answers.
     *
     * @param  ?\SineMacula\Laravel\Sso\Connections\ConnectionSummary  $connection
     * @return mixed
     */
    private function import(?ConnectionSummary $connection): mixed
    {
        return self::atEndpoint('import', ['tenant' => $this->tenant, 'connection' => $connection]);
    }

    /**
     * The proposal the import endpoint shows for the connection.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\ProposedSettings
     */
    private function proposed(): ProposedSettings
    {
        $shown = $this->import($this->connection);

        self::assertIsArray($shown);
        self::assertInstanceOf(ProposedSettings::class, $shown['proposed']);

        return $shown['proposed'];
    }

    /**
     * Run the save endpoint for the proposal as the administrator, and answer
     * what it answers.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\ProposedSettings  $proposed
     * @return mixed
     */
    private function save(ProposedSettings $proposed): mixed
    {
        return self::atEndpoint('save', [
            'tenant'     => $this->tenant,
            'connection' => $this->connection,
            'proposed'   => $proposed,
            'actor'      => self::actor(),
        ]);
    }
}
