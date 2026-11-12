<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\ImportSaver;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Metadata\DiscoveryImporter;
use SineMacula\Laravel\Sso\Metadata\MetadataImporter;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;

/**
 * The testing guide's metadata examples: SAML metadata and an OpenID discovery
 * document imported through the fake fetcher.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeFetcher::class)]
#[CoversClass(FakeSamlIdentityProvider::class)]
#[CoversClass(FakeOpenIdProvider::class)]
final class MetadataExampleTest extends ExampleTestCase
{
    /** @var string Where the SAML provider publishes its metadata. */
    private const string METADATA_URL = 'https://idp.example.test/metadata';

    /**
     * Imported SAML metadata proposes settings and a certificate that make a
     * usable connection.
     *
     * @return void
     */
    public function testImportingSamlMetadata(): void
    {
        $client = Clients::browser();
        // @snippet-start saml-metadata
        $idp = new FakeSamlIdentityProvider;

        $this->fetcher->respond('https://idp.example.test/metadata', FetchResult::fetched(200, [], $idp->metadata()->toXml()));

        $imported = app(MetadataImporter::class)->importUrl(self::TENANT, null, 'https://idp.example.test/metadata', $idp->entityId);
        $proposed = $imported->proposed;

        self::assertNotNull($proposed);
        self::assertSame([$idp->entityId, FakeSamlIdentityProvider::SSO_URL], [$proposed->settings()['idp_entity_id'], $proposed->settings()['sso_url']]);
        self::assertCount(1, $proposed->signingCertificates());

        $this->fetcher->assertFetched('https://idp.example.test/metadata', FetchPurpose::METADATA);

        // The administrator accepts the proposal, having compared the
        // fingerprint
        $connections  = app(ConnectionService::class);
        $connectionId = (string) $connections->create(self::TENANT, 'saml2', 'Imported SAML', $client, $proposed->settings())->connection?->id;

        app(KeyService::class)->trustCertificate(self::TENANT, $connectionId, $proposed->signingCertificates()[0]['certificate'], $client);
        $connections->enable(self::TENANT, $connectionId, $client);

        self::assertTrue($connections->get(self::TENANT, $connectionId)?->usable);
        // @snippet-end saml-metadata
    }

    /**
     * A metadata URL that does not answer `2xx` is refused with `fetch_failed`.
     *
     * @return void
     */
    public function testAFailingMetadataUrlIsRefused(): void
    {
        // @snippet-start saml-metadata-refused
        $this->fetcher->respond(self::METADATA_URL, FetchResult::fetched(500, [], 'Internal Server Error'));

        $imported = app(MetadataImporter::class)->importUrl(self::TENANT, null, self::METADATA_URL, FakeSamlIdentityProvider::ENTITY_ID);

        self::assertTrue($imported->isRefused());
        self::assertSame(FailureReason::FETCH_FAILED, $imported->reason);
        // @snippet-end saml-metadata-refused
    }

    /**
     * An imported discovery document proposes endpoints that are saved with
     * their fetch.
     *
     * @return void
     */
    public function testImportingAnOpenIdProvidersDiscoveryDocument(): void
    {
        $client = Clients::browser();
        // @snippet-start oidc-discovery
        $provider = (new FakeOpenIdProvider(clock: $this->clock))->serve($this->fetcher);

        $connections  = app(ConnectionService::class);
        $connectionId = (string) $connections->create(self::TENANT, 'oidc', 'Discovered OIDC', $client, [
            'client_id'     => FakeOpenIdProvider::CLIENT_ID,
            'client_secret' => FakeOpenIdProvider::CLIENT_SECRET,
        ])->connection?->id;

        $imported = app(DiscoveryImporter::class)->import(self::TENANT, $provider->issuer, $connectionId);
        $proposed = $imported->proposed;

        self::assertNotNull($proposed);
        self::assertSame($provider->endpoint('jwks'), $proposed->settings()['jwks_uri']);

        $this->fetcher->assertFetched($provider->discoveryUrl(), FetchPurpose::DISCOVERY);
        $this->fetcher->assertFetched($provider->endpoint('jwks'), FetchPurpose::JWKS);

        app(ImportSaver::class)->save(self::TENANT, $connectionId, ['settings' => $proposed->settings()], $proposed->fetch(), $client);
        $connections->enable(self::TENANT, $connectionId, $client);

        self::assertTrue($connections->get(self::TENANT, $connectionId)?->usable);
        // @snippet-end oidc-discovery
    }

    /**
     * A document naming another issuer is refused with `issuer_mismatch`.
     *
     * @return void
     */
    public function testADocumentNamingAnotherIssuerIsRefused(): void
    {
        // @snippet-start oidc-discovery-refused
        $provider = (new FakeOpenIdProvider('https://op.example.test', clock: $this->clock))
            ->withDiscovery(['issuer' => 'https://elsewhere.example.test'])
            ->serve($this->fetcher);

        $imported = app(DiscoveryImporter::class)->import(self::TENANT, $provider->issuer);

        self::assertTrue($imported->isRefused());
        self::assertSame(FailureReason::ISSUER_MISMATCH, $imported->reason);
        // @snippet-end oidc-discovery-refused
    }
}
