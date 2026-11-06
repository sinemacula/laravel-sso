<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Metadata\ImportResult;
use SineMacula\Laravel\Sso\Metadata\MetadataImporter;
use SineMacula\Laravel\Sso\Metadata\ProposedSettings;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\RateLimit;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for importing a SAML identity provider's metadata (SSO-2.8,
 * SSO-2.9, SSO-2.11): from XML or a URL fetched through the fetcher as a
 * metadata request, the settings proposed exactly, the connection's binding
 * preferred and its anchors applied; an unknown, another tenant's or a non-SAML
 * connection refused; a refused or failed fetch refused with its reason; the
 * reader's refusal passed on with its rule; a proposal that would not be valid
 * settings refused; a URL import of a connection rate limited before it
 * fetches; every import refused while SAML is off; and nothing written, trusted
 * or reported.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataImporter::class)]
#[CoversClass(ImportResult::class)]
#[CoversClass(ProposedSettings::class)]
final class MetadataImporterTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /** @var string The tenant importing. */
    private const string TENANT = 'tenant-1';

    /** @var string The URL the metadata is served at. */
    private const string URL = 'https://idp.example.test/metadata.xml';

    /** @var string The HTTP-POST single sign-on URL the metadata names besides. */
    private const string POST_URL = 'https://idp.example.test/saml/post';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the importer fetches through. */
    private FakeFetcher $fetcher;

    /**
     * Bind a fixed clock and a fake fetcher, switch SAML on, create the tables
     * and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher = new FakeFetcher;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Fetcher::class, $this->fetcher);

        config()->set('sso.features.saml2', true);

        $this->usePackageTables();

        $this->startRecordingEvents();
    }

    /**
     * Metadata given as XML proposes the entity's settings, certificates,
     * NameID formats and expiry, and nothing is fetched, written, trusted or
     * reported.
     *
     * @return void
     */
    public function testXmlProposesTheEntitysSettings(): void
    {
        $xml = self::metadata()->with([
            'encryption_certificates' => [Certificates::distinct(3)],
            'name_id_formats'         => [FakeSamlResponse::PERSISTENT, 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
            'valid_until'             => CarbonImmutable::parse('2026-12-01T00:00:00Z'),
        ])->toXml();

        $result = $this->importer()->importXml(self::TENANT, null, $xml, FakeSamlIdentityProvider::ENTITY_ID);

        self::assertTrue($result->isProposed());
        self::assertFalse($result->isRefused());
        self::assertFalse($result->isRateLimited());
        self::assertNull($result->reason);
        self::assertNull($result->detail);
        self::assertNull($result->retryAfter);
        self::assertSame([
            ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL, 'sso_binding' => 'http_redirect'],
            [self::certificate(self::idp()->certificate())],
            [self::certificate(Certificates::distinct(3))],
            [FakeSamlResponse::PERSISTENT, 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
            '2026-12-01T00:00:00+00:00',
        ], self::proposal($result));

        $this->fetcher->assertNothingFetched();
        $this->assertNothingWritten();
    }

    /**
     * Naming the tenant's SAML connection prefers the binding it uses.
     *
     * @return void
     */
    public function testNamingAConnectionPrefersItsBinding(): void
    {
        $xml  = self::metadata()->with(['post_sso_url' => self::POST_URL])->toXml();
        $post = $this->saml(['sso_binding' => 'http_post']);

        $proposed = $this->importer()->importXml(self::TENANT, $post->id, $xml, FakeSamlIdentityProvider::ENTITY_ID)->proposed?->settings() ?? [];

        self::assertSame(['http_post', self::POST_URL], [$proposed['sso_binding'] ?? null, $proposed['sso_url'] ?? null]);
        self::assertSame('http_redirect', $this->importer()->importXml(self::TENANT, null, $xml, FakeSamlIdentityProvider::ENTITY_ID)->proposed?->settings()['sso_binding']);
    }

    /**
     * A connection with a metadata signing anchor refuses unsigned metadata and
     * metadata the anchor did not sign, and reads metadata it signed; an import
     * naming no connection applies no anchor.
     *
     * @return void
     */
    public function testAConnectionsAnchorsApply(): void
    {
        $connection = $this->saml();
        $attacker   = new FakeSamlIdentityProvider('https://attacker.example.test/saml');

        $this->trust($connection, KeyUse::METADATA_SIGNING, self::idp()->certificate());
        $this->trust($connection, KeyUse::IDP_SIGNING, Certificates::distinct(4));

        $forgedXml = self::metadata()->with(['sign' => 'entity'])->signedBy($attacker->signer())->toXml();
        $unsigned  = $this->importer()->importXml(self::TENANT, $connection->id, self::metadata()->toXml(), FakeSamlIdentityProvider::ENTITY_ID);
        $forged    = $this->importer()->importXml(self::TENANT, $connection->id, $forgedXml, FakeSamlIdentityProvider::ENTITY_ID);
        $signed    = $this->importer()->importXml(self::TENANT, $connection->id, self::metadata()->with(['sign' => 'entity'])->toXml(), FakeSamlIdentityProvider::ENTITY_ID);

        self::assertSame([FailureReason::METADATA_SIGNATURE_INVALID, 'unsigned'], [$unsigned->reason, $unsigned->detail]);
        self::assertSame([FailureReason::METADATA_SIGNATURE_INVALID, 'signature'], [$forged->reason, $forged->detail]);
        self::assertTrue($signed->isProposed());
        self::assertTrue($this->importer()->importXml(self::TENANT, null, self::metadata()->toXml(), FakeSamlIdentityProvider::ENTITY_ID)->isProposed());
    }

    /**
     * Rows of `[connection]`: what makes a named connection not found.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnknownConnections(): iterable
    {
        yield from [
            'an unknown connection'      => ['unknown'],
            'another tenants connection' => ['other-tenant'],
            'an OIDC connection'         => ['oidc'],
        ];
    }

    /**
     * An unknown connection, another tenant's and one that is not SAML are not
     * found, by either import, and nothing is fetched.
     *
     * @param  string  $kind
     * @return void
     */
    #[DataProvider('provideUnknownConnections')]
    public function testAConnectionThatIsNotTheTenantsSamlConnectionIsNotFound(string $kind): void
    {
        $id = match ($kind) {
            'unknown'      => '01jbunknownconnection00000',
            'other-tenant' => $this->saml([], 'tenant-2')->id,
            default        => $this->makeConnection(['protocol' => 'oidc'])->id,
        };

        $xml = $this->importer()->importXml(self::TENANT, $id, self::metadata()->toXml(), FakeSamlIdentityProvider::ENTITY_ID);
        $url = $this->importer()->importUrl(self::TENANT, $id, self::URL, FakeSamlIdentityProvider::ENTITY_ID);

        foreach ([$xml, $url] as $result) {
            self::assertTrue($result->isRefused());
            self::assertSame([FailureReason::CONNECTION_NOT_FOUND, null], [$result->reason, $result->detail]);
        }

        $this->fetcher->assertNothingFetched();
    }

    /**
     * While the SAML protocol is off, every import, naming a connection or not,
     * is refused as `protocol_unavailable`, with nothing fetched, counted or
     * reported.
     *
     * @return void
     */
    public function testEveryImportIsRefusedWhileSamlIsOff(): void
    {
        config()->set('sso.rate_limits.metadata.per_connection', ['max' => 1, 'decay_seconds' => 3600]);

        $connection = $this->saml();

        config()->set('sso.features.saml2', false);

        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], self::metadata()->toXml()));

        $results = [];

        foreach ([null, $connection->id] as $id) {
            $results[] = $this->importer()->importXml(self::TENANT, $id, self::metadata()->toXml(), FakeSamlIdentityProvider::ENTITY_ID);
            $results[] = $this->importer()->importUrl(self::TENANT, $id, self::URL, FakeSamlIdentityProvider::ENTITY_ID);
            $results[] = $this->importer()->importUrl(self::TENANT, $id, self::URL, FakeSamlIdentityProvider::ENTITY_ID);
        }

        $shown = array_map(static fn (ImportResult $result): array => [$result->reason, $result->detail, $result->proposed, $result->retryAfter, $result->isRefused()], $results);

        self::assertSame(array_fill(0, 6, [FailureReason::PROTOCOL_UNAVAILABLE, null, null, null, true]), $shown);

        $this->fetcher->assertNothingFetched();
        self::assertSame(0, RateLimit::query()->count());
        $this->assertNoEvents();
    }

    /**
     * A tenant id the connections table cannot hold is the application's
     * mistake, named or not; one of 255 bytes is accepted.
     *
     * @return void
     */
    public function testATenantIdOfTheWrongLengthIsAMistake(): void
    {
        self::assertTrue($this->importer()->importXml(str_repeat('t', 255), null, self::metadata()->toXml(), FakeSamlIdentityProvider::ENTITY_ID)->isProposed());

        foreach (['', str_repeat('t', 256)] as $tenant) {
            try {
                $this->importer()->importXml($tenant, null, self::metadata()->toXml(), FakeSamlIdentityProvider::ENTITY_ID);
                self::fail('A malformed tenant id was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A tenant id is 1 to 255 bytes.', $exception->getMessage());
            }
        }
    }

    /**
     * A URL is fetched through the fetcher as a metadata request, with no
     * credential, and its metadata proposes the settings; nothing is written.
     *
     * @return void
     */
    public function testAUrlIsFetchedAsAMetadataRequest(): void
    {
        $connection = $this->saml();

        $this->fetcher->respond(self::URL, FetchResult::fetched(200, ['content-type' => 'application/samlmetadata+xml'], self::metadata()->toXml()));

        $result = $this->importer()->importUrl(self::TENANT, $connection->id, self::URL, FakeSamlIdentityProvider::ENTITY_ID);

        self::assertSame(FakeSamlIdentityProvider::ENTITY_ID, $result->proposed?->settings()['idp_entity_id']);
        self::assertCount(1, $this->fetcher->requests());
        self::assertSame([FetchPurpose::METADATA, self::URL, null, 'GET', 1048576], [
            $this->fetcher->requests()[0]->purpose,
            $this->fetcher->requests()[0]->url,
            $this->fetcher->requests()[0]->credentials,
            $this->fetcher->requests()[0]->method(),
            $this->fetcher->requests()[0]->maxBytes,
        ]);

        $this->assertNoEvents();
    }

    /**
     * Rows of `[cap, imported]`: the metadata cap one over, at and one under
     * the document's length, and whether the import proposes settings.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideCaps(): iterable
    {
        yield from [
            'one under the cap' => [70001, true],
            'at the cap'        => [70000, true],
            'one over the cap'  => [69999, false],
        ];
    }

    /**
     * A URL is fetched held to the metadata cap, never the fetcher's, and a
     * fetched document over it fails the fetch; one at or under it is imported,
     * however small the fetcher's own cap.
     *
     * @param  int  $cap
     * @param  bool  $imported
     * @return void
     */
    #[DataProvider('provideCaps')]
    public function testAUrlIsFetchedHeldToTheMetadataCap(int $cap, bool $imported): void
    {
        config()->set('sso.metadata.max_bytes', $cap);
        config()->set('sso.fetcher.max_response_bytes', 1024);

        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], str_pad(self::metadata()->toXml(), 70000, "\n")));

        $result = $this->importer()->importUrl(self::TENANT, null, self::URL, FakeSamlIdentityProvider::ENTITY_ID);

        self::assertSame($cap, $this->fetcher->requests()[0]->maxBytes);
        self::assertSame([$imported, $imported ? null : FailureReason::FETCH_FAILED], [$result->isProposed(), $result->reason]);
    }

    /**
     * Metadata given as XML is held to the same cap before it is parsed.
     *
     * @return void
     */
    public function testXmlIsHeldToTheMetadataCap(): void
    {
        $xml = str_pad(self::metadata()->toXml(), 70000, "\n");

        config()->set('sso.metadata.max_bytes', 69999);

        $refused = $this->importer()->importXml(self::TENANT, null, $xml, FakeSamlIdentityProvider::ENTITY_ID);

        self::assertSame([FailureReason::METADATA_INVALID, 'too_large'], [$refused->reason, $refused->detail]);

        config()->set('sso.metadata.max_bytes', 70000);

        self::assertTrue($this->importer()->importXml(self::TENANT, null, $xml, FakeSamlIdentityProvider::ENTITY_ID)->isProposed());
    }

    /**
     * Rows of `[response, reason]`: a fetch that brought no metadata, and the
     * reason the import is refused for.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchResult, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideFailedFetches(): iterable
    {
        yield from [
            'refused'              => [FetchResult::refused(), FailureReason::FETCH_REFUSED],
            'failed'               => [FetchResult::failed(), FailureReason::FETCH_FAILED],
            'not found'            => [FetchResult::fetched(404, [], 'missing'), FailureReason::FETCH_FAILED],
            'a server error'       => [FetchResult::fetched(500, [], ''), FailureReason::FETCH_FAILED],
            'a redirect not taken' => [FetchResult::fetched(302, ['location' => 'https://elsewhere.example.test'], ''), FailureReason::FETCH_FAILED],
        ];
    }

    /**
     * A fetch refused, failed or answered with anything but `2xx` is refused
     * with its reason.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $response
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideFailedFetches')]
    public function testAFetchThatBroughtNoMetadataIsRefused(FetchResult $response, FailureReason $reason): void
    {
        $this->fetcher->respond(self::URL, $response);

        $result = $this->importer()->importUrl(self::TENANT, null, self::URL, FakeSamlIdentityProvider::ENTITY_ID);

        self::assertTrue($result->isRefused());
        self::assertSame([$reason, null, null], [$result->reason, $result->detail, $result->proposed]);
    }

    /**
     * Each URL import naming a connection counts against its metadata limit
     * before it fetches: past the limit it is rate limited until the window
     * ends, with nothing fetched; an import naming no connection, or given as
     * XML, is not counted.
     *
     * @return void
     */
    public function testAUrlImportOfAConnectionIsRateLimited(): void
    {
        config()->set('sso.rate_limits.metadata.per_connection', ['max' => 2, 'decay_seconds' => 3600]);

        $connection = $this->saml();

        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], self::metadata()->toXml()));

        self::assertTrue($this->importer()->importXml(self::TENANT, $connection->id, self::metadata()->toXml(), FakeSamlIdentityProvider::ENTITY_ID)->isProposed());
        self::assertTrue($this->importer()->importUrl(self::TENANT, $connection->id, self::URL, FakeSamlIdentityProvider::ENTITY_ID)->isProposed());
        self::assertTrue($this->importer()->importUrl(self::TENANT, $connection->id, self::URL, FakeSamlIdentityProvider::ENTITY_ID)->isProposed());

        $limited = $this->importer()->importUrl(self::TENANT, $connection->id, self::URL, FakeSamlIdentityProvider::ENTITY_ID);

        self::assertTrue($limited->isRateLimited());
        self::assertFalse($limited->isRefused());
        self::assertFalse($limited->isProposed());
        self::assertSame([FailureReason::RATE_LIMITED, 1800], [$limited->reason, $limited->retryAfter]);
        self::assertCount(2, $this->fetcher->requests());

        foreach (range(1, 3) as $attempt) {
            self::assertTrue($this->importer()->importUrl(self::TENANT, null, self::URL, FakeSamlIdentityProvider::ENTITY_ID)->isProposed(), "Attempt {$attempt}");
        }
    }

    /**
     * The reader's refusal is passed on with the rule that refused the
     * metadata.
     *
     * @return void
     */
    public function testTheReadersRefusalIsPassedOn(): void
    {
        $missing = $this->importer()->importXml(self::TENANT, null, self::metadata()->toXml(), 'https://nobody.example.test/saml');
        $lapsed  = self::metadata()->with(['valid_until' => CarbonImmutable::parse('2026-11-01T09:30:00Z')])->toXml();
        $expired = $this->importer()->importXml(self::TENANT, null, $lapsed, FakeSamlIdentityProvider::ENTITY_ID);
        $invalid = $this->importer()->importXml(self::TENANT, null, 'not metadata', FakeSamlIdentityProvider::ENTITY_ID);

        self::assertSame([FailureReason::METADATA_ENTITY_NOT_FOUND, 'entity_not_found'], [$missing->reason, $missing->detail]);
        self::assertSame([FailureReason::METADATA_EXPIRED, 'expired'], [$expired->reason, $expired->detail]);
        self::assertSame([FailureReason::METADATA_INVALID, 'unparseable'], [$invalid->reason, $invalid->detail]);
    }

    /**
     * Rows of `[changes, entity id]`: metadata proposing settings a connection
     * cannot hold.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideInvalidProposals(): iterable
    {
        yield from [
            'a single sign-on URL over HTTP'       => [['sso_url' => 'http://idp.example.test/sso'], FakeSamlIdentityProvider::ENTITY_ID],
            'a single sign-on URL with a fragment' => [['sso_url' => 'https://idp.example.test/sso#top'], FakeSamlIdentityProvider::ENTITY_ID],
            'an entity id that is not a URI'       => [['entity_id' => 'idp-entity'], 'idp-entity'],
        ];
    }

    /**
     * Metadata proposing settings a connection could not hold is refused.
     *
     * @param  array<string, mixed>  $changes
     * @param  string  $entityId
     * @return void
     */
    #[DataProvider('provideInvalidProposals')]
    public function testAProposalThatWouldNotBeValidSettingsIsRefused(array $changes, string $entityId): void
    {
        $result = $this->importer()->importXml(self::TENANT, null, self::metadata()->with($changes)->toXml(), $entityId);

        self::assertSame([FailureReason::METADATA_INVALID, 'settings', null], [$result->reason, $result->detail, $result->proposed]);
    }

    /**
     * An import is refused only for its own reasons, and rate limited for at
     * least a second.
     *
     * @return void
     */
    public function testAResultHoldsOnlyItsOwnReasons(): void
    {
        self::assertSame(
            [
                FailureReason::PROTOCOL_UNAVAILABLE, FailureReason::CONNECTION_NOT_FOUND, FailureReason::FETCH_REFUSED, FailureReason::FETCH_FAILED,
                FailureReason::METADATA_INVALID, FailureReason::METADATA_SIGNATURE_INVALID, FailureReason::METADATA_ENTITY_NOT_FOUND,
                FailureReason::METADATA_EXPIRED,
            ],
            ImportResult::REFUSALS,
        );
        self::assertSame(1, ImportResult::rateLimited(1)->retryAfter);

        $rows = [
            [static fn (): ImportResult => ImportResult::refused(FailureReason::RATE_LIMITED), 'An import is not refused for [rate_limited].'],
            [static fn (): ImportResult => ImportResult::rateLimited(0), 'A rate limited import may be tried again after at least 1 second.'],
        ];

        foreach ($rows as [$build, $expected]) {
            try {
                $build();
                self::fail('An impossible result was built.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($expected, $exception->getMessage());
            }
        }
    }

    /**
     * What an import proposes shows in a dump and JSON as names and counts,
     * never a value, and refuses to be serialised.
     *
     * @return void
     */
    public function testTheProposalIsRedacted(): void
    {
        $xml      = self::metadata()->with(['valid_until' => CarbonImmutable::parse('2026-12-01T00:00:00Z')])->toXml();
        $proposed = $this->importer()->importXml(self::TENANT, null, $xml, FakeSamlIdentityProvider::ENTITY_ID)->proposed;

        self::assertNotNull($proposed);

        $shown = [
            'settings'                => ['idp_entity_id', 'sso_url', 'sso_binding'],
            'signing_certificates'    => 1,
            'encryption_certificates' => 0,
            'name_id_formats'         => 1,
            'valid_until'             => '[redacted]',
        ];

        self::assertSame($shown, $proposed->__debugInfo());
        self::assertSame((string) json_encode($shown), json_encode($proposed));
        self::assertStringNotContainsString(FakeSamlIdentityProvider::SSO_URL, print_r($proposed, true));

        $attempts = [
            [static fn (): string => serialize($proposed), 'Proposed settings cannot be serialised.'],
            [
                static fn (): mixed => unserialize('O:' . strlen(ProposedSettings::class) . ':"' . ProposedSettings::class . '":0:{}'),
                'Proposed settings cannot be unserialised.',
            ],
        ];

        foreach ($attempts as [$attempt, $expected]) {
            try {
                $attempt();
                self::fail('A proposal crossed a serialisation.');
            } catch (\LogicException $exception) {
                self::assertSame($expected, $exception->getMessage());
            }
        }
    }

    /**
     * Assert no connection or key was written and no event reported.
     *
     * @return void
     */
    private function assertNothingWritten(): void
    {
        self::assertSame(0, Connection::query()->count());
        self::assertSame(0, ConnectionKey::query()->count());
        $this->assertNoEvents();
    }

    /**
     * Everything the import proposed, in order.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\ImportResult  $result
     * @return list<mixed>
     */
    private static function proposal(ImportResult $result): array
    {
        $proposed = $result->proposed;

        self::assertNotNull($proposed);

        return [
            $proposed->settings(),
            $proposed->signingCertificates(),
            $proposed->encryptionCertificates(),
            $proposed->nameIdFormats(),
            $proposed->validUntil()?->toIso8601String(),
        ];
    }

    /**
     * The certificate as the import proposes it: its canonical PEM and its
     * fingerprint.
     *
     * @param  string  $pem
     * @return array{certificate: string, fingerprint: string}
     */
    private static function certificate(string $pem): array
    {
        $masked = MaskedKey::fromCertificate($pem);

        return ['certificate' => (string) $masked->certificate, 'fingerprint' => (string) $masked->fingerprint];
    }

    /**
     * A SAML connection of the tenant with the settings given.
     *
     * @param  array<string, mixed>  $settings
     * @param  string  $tenant
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(array $settings = [], string $tenant = self::TENANT): Connection
    {
        return $this->makeConnection([
            'tenant_id' => $tenant,
            'protocol'  => 'saml2',
            'settings'  => [
                'idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID,
                'sso_url'       => FakeSamlIdentityProvider::SSO_URL,
                'sso_binding'   => 'http_redirect',
                ...$settings,
            ],
        ]);
    }

    /**
     * Trust the certificate for the connection and the use.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  string  $certificate
     * @return void
     */
    private function trust(Connection $connection, KeyUse $use, string $certificate): void
    {
        $masked = MaskedKey::fromCertificate($certificate);

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => $use,
            'state'         => null,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $masked->certificate,
            'public_key'    => $masked->publicKey,
            'private_key'   => null,
            'fingerprint'   => $masked->fingerprint,
        ])->save();
    }

    /**
     * The importer, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\MetadataImporter
     */
    private function importer(): MetadataImporter
    {
        return app(MetadataImporter::class);
    }

    /**
     * The provider's unsigned metadata.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata
     */
    private static function metadata(): FakeSamlMetadata
    {
        return self::idp()->metadata();
    }

    /**
     * The provider, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }
}
