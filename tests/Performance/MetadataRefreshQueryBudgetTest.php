<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\MetadataApplier;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\RefreshResult;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Keys\Certificates;

/**
 * Query budgets for a metadata refresh: a counted, claimed fetch, then one
 * transaction that writes only what changed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataRefresher::class)]
#[CoversClass(MetadataApplier::class)]
final class MetadataRefreshQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections;

    /** @var string The tenant whose connection refreshes. */
    private const string TENANT = 'tenant-1';

    /** @var string The URL the provider serves its metadata at. */
    private const string URL = 'https://idp.example.test/metadata.xml';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the refresh fetches through. */
    private FakeFetcher $fetcher;

    /**
     * Bind a fake fetcher and switch SAML and the refresh on.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher = new FakeFetcher;

        $this->app?->instance(Fetcher::class, $this->fetcher);

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.metadata_refresh', true);
    }

    /**
     * The connection, anchors, certificates, three locked reads and the
     * insert's check; the counter's two, the claim, the insert and refresh.
     *
     * @return void
     */
    public function testARefreshAddingACertificateIsSevenReadsAndFiveWrites(): void
    {
        $connection = $this->saml([self::idp()->certificate()]);

        $this->serve(self::idp()->metadata()->with(['signing_certificates' => [self::idp()->certificate(), Certificates::distinct(0)]]));

        $result = $this->assertQueryBudget(7, 5, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor(), Clients::browser()));

        self::assertSame([RefreshOutcome::REFRESHED, ['idp_signing_certificates'], false], [$result->outcome, $result->changedSettings, $result->trustChanged]);
    }

    /**
     * The listing and the anchors of all of them at once; only the connection
     * with an anchor is due.
     *
     * @return void
     */
    public function testListingManyConnectionsReadsTheirAnchorsOnce(): void
    {
        $connections = array_map(fn (): Connection => $this->switched(null), range(1, 5));

        $this->trust($connections[2], self::idp()->certificate(), KeyUse::METADATA_SIGNING);

        $due = $this->assertQueryBudget(2, 0, fn (): array => $this->refresher()->dueConnectionIds());

        self::assertSame([$connections[2]->id], $due);
    }

    /**
     * A connection whose switch decides for it reads no anchor.
     *
     * @return void
     */
    public function testListingConnectionsWithASwitchSetReadsNoAnchor(): void
    {
        $on = $this->switched(true);

        $this->switched(false);

        self::assertSame([$on->id], $this->assertQueryBudget(1, 0, fn (): array => $this->refresher()->dueConnectionIds()));
    }

    /**
     * The counter's two writes, the claim, the delete, the voiding's four
     * writes and one update of settings and refresh; trust is raised once.
     *
     * @return void
     */
    public function testARefreshRemovingACertificateAndMovingTheEndpointIsSixReadsAndNineWrites(): void
    {
        $connection = $this->saml([self::idp()->certificate(), Certificates::distinct(0)]);

        $this->serve(self::idp()->metadata('https://login.example.test/saml/sso'));

        $result = $this->assertQueryBudget(6, 9, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor(), Clients::browser()));

        self::assertSame([RefreshOutcome::REFRESHED, ['sso_url', 'idp_signing_certificates'], true], [$result->outcome, $result->changedSettings, $result->trustChanged]);
    }

    /**
     * The listing, anchors, certificates and three locked reads; the claim and
     * the refresh, with nothing counted.
     *
     * @return void
     */
    public function testAScheduledRefreshChangingNothingIsSixReadsAndTwoWrites(): void
    {
        $this->saml([self::idp()->certificate()]);
        $this->serve(self::idp()->metadata());

        $results = $this->assertQueryBudget(6, 2, fn (): array => $this->refresher()->refreshDue(Clients::browser()));

        self::assertSame([RefreshOutcome::REFRESHED], array_map(static fn (RefreshResult $result): RefreshOutcome => $result->outcome, $results));
    }

    /**
     * The connection, anchors, certificates and two locked reads; the counter's
     * two writes, the claim and the failure.
     *
     * @return void
     */
    public function testAFailedRefreshIsFiveReadsAndFourWrites(): void
    {
        $connection = $this->saml([self::idp()->certificate()]);

        $this->fetcher->respond(self::URL, FetchResult::failed());

        $result = $this->assertQueryBudget(5, 4, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor(), Clients::browser()));

        self::assertSame(RefreshOutcome::FAILED, $result->outcome);
    }

    /**
     * A claim another server holds: three reads, the counter's two writes and a
     * claim update that changes no row.
     *
     * @return void
     */
    public function testARefreshWhoseClaimIsHeldIsThreeReadsAndThreeWrites(): void
    {
        $connection = $this->saml([self::idp()->certificate()], ['metadata_claimed_until' => $this->clock->now()->addMinute()]);

        $result = $this->assertQueryBudget(3, 3, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor(), Clients::browser()));

        self::assertSame(RefreshOutcome::IN_PROGRESS, $result->outcome);

        $this->fetcher->assertNothingFetched();
    }

    /**
     * The connection and the full counter; its update, refused insert and
     * update again, none changing a row. Nothing is fetched.
     *
     * @return void
     */
    public function testARateLimitedRefreshIsTwoReadsAndThreeWrites(): void
    {
        config()->set('sso.rate_limits.metadata.per_connection', ['max' => 1, 'decay_seconds' => 3600]);

        $connection = $this->saml([self::idp()->certificate()], ['metadata_claimed_until' => $this->clock->now()->addMinute()]);

        $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor(), Clients::browser());

        $result = $this->assertQueryBudget(2, 3, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor(), Clients::browser()));

        self::assertSame(RefreshOutcome::RATE_LIMITED, $result->outcome);

        $this->fetcher->assertNothingFetched();
    }

    /**
     * A refreshing SAML connection trusting the certificates.
     *
     * @param  list<string>  $certificates
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(array $certificates, array $attributes = []): Connection
    {
        $connection = $this->makeConnection(['protocol' => 'saml2', 'enabled' => true, 'settings' => [
            'idp_entity_id'    => FakeSamlIdentityProvider::ENTITY_ID,
            'sso_url'          => FakeSamlIdentityProvider::SSO_URL,
            'sso_binding'      => 'http_redirect',
            'metadata_url'     => self::URL,
            'metadata_refresh' => true,
        ], ...$attributes]);

        foreach ($certificates as $certificate) {
            $this->trust($connection, $certificate, KeyUse::IDP_SIGNING);
        }

        return $connection;
    }

    /**
     * A SAML connection with a URL and the switch given, trusting nothing.
     *
     * @param  ?bool  $switch
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function switched(?bool $switch): Connection
    {
        return $this->saml([], ['settings' => array_filter(['metadata_url' => self::URL, 'metadata_refresh' => $switch], static fn (mixed $value): bool => $value !== null)]);
    }

    /**
     * Trust the certificate for the connection and the use.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $certificate
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return void
     */
    private function trust(Connection $connection, string $certificate, KeyUse $use): void
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
     * Serve the metadata at the URL.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata  $metadata
     * @return void
     */
    private function serve(FakeSamlMetadata $metadata): void
    {
        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], $metadata->toXml()));
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
     * The provider, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }

    /**
     * The administrator who asks for a refresh now.
     *
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     */
    private static function actor(): Caller
    {
        return new Caller(new IdentityReference('App\Models\User', '42'));
    }
}
