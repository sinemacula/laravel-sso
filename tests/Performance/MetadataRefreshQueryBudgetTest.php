<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
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
use Tests\Fixtures\Keys\Certificates;

/**
 * Query budgets for a metadata refresh (SSO-2.8, SSO-11.12). Before it fetches,
 * a refresh reads the connection (an administrator's by its id, the schedule's
 * in the due listing) and its anchors, and claims it with one conditional
 * update; after, in one transaction, it reads the connection locked, its
 * anchors and its trusted certificates locked, and writes only what changed:
 *
 * - a refresh now that adds a certificate: 6 reads (the connection and the
 *   anchors; the connection, the anchors and the certificates locked; the
 *   fingerprints judged before the insert) and 3 writes (the claim, the
 *   insert, the connection's refresh);
 * - a refresh now that removes a certificate and moves the endpoint: 5 reads
 *   and 6 writes (the claim, the delete, the requests and the handoff codes
 *   voided, the trust version raised once, the connection's settings and
 *   refresh in one update);
 * - a scheduled refresh of one connection that changes nothing: 5 reads (the
 *   listing, the anchors, then the three locked reads) and 2 writes (the
 *   claim, the refresh);
 * - a failed refresh: 3 reads (the connection, the anchors, the connection
 *   locked) and 2 writes (the claim, the failure);
 * - a refresh now whose claim another server holds: 2 reads and the claim's
 *   update, which changes no row.
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
     * A refresh now that adds a certificate is six reads and three writes.
     *
     * @return void
     */
    public function testARefreshAddingACertificateIsSixReadsAndThreeWrites(): void
    {
        $connection = $this->saml([self::idp()->certificate()]);

        $this->serve(self::idp()->metadata()->with(['signing_certificates' => [self::idp()->certificate(), Certificates::distinct(0)]]));

        $result = $this->assertQueryBudget(6, 3, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id));

        self::assertSame([RefreshOutcome::REFRESHED, ['idp_signing_certificates'], false], [$result->outcome, $result->changedSettings, $result->trustChanged]);
    }

    /**
     * A refresh now that removes a certificate and moves the endpoint is five
     * reads and six writes, the trust version raised once.
     *
     * @return void
     */
    public function testARefreshRemovingACertificateAndMovingTheEndpointIsFiveReadsAndSixWrites(): void
    {
        $connection = $this->saml([self::idp()->certificate(), Certificates::distinct(0)]);

        $this->serve(self::idp()->metadata('https://login.example.test/saml/sso'));

        $result = $this->assertQueryBudget(5, 6, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id));

        self::assertSame([RefreshOutcome::REFRESHED, ['sso_url', 'idp_signing_certificates'], true], [$result->outcome, $result->changedSettings, $result->trustChanged]);
    }

    /**
     * A scheduled refresh of one connection that changes nothing is five reads
     * and two writes.
     *
     * @return void
     */
    public function testAScheduledRefreshChangingNothingIsFiveReadsAndTwoWrites(): void
    {
        $this->saml([self::idp()->certificate()]);
        $this->serve(self::idp()->metadata());

        $results = $this->assertQueryBudget(5, 2, fn (): array => $this->refresher()->refreshDue());

        self::assertSame([RefreshOutcome::REFRESHED], array_map(static fn (RefreshResult $result): RefreshOutcome => $result->outcome, $results));
    }

    /**
     * A failed refresh is three reads and two writes.
     *
     * @return void
     */
    public function testAFailedRefreshIsThreeReadsAndTwoWrites(): void
    {
        $connection = $this->saml([self::idp()->certificate()]);

        $this->fetcher->respond(self::URL, FetchResult::failed());

        $result = $this->assertQueryBudget(3, 2, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id));

        self::assertSame(RefreshOutcome::FAILED, $result->outcome);
    }

    /**
     * A refresh now whose claim another server holds is two reads and the
     * claim's update, and fetches nothing.
     *
     * @return void
     */
    public function testARefreshWhoseClaimIsHeldIsTwoReadsAndTheClaim(): void
    {
        $connection = $this->saml([self::idp()->certificate()], ['metadata_claimed_until' => $this->clock->now()->addMinute()]);

        $result = $this->assertQueryBudget(2, 1, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id));

        self::assertSame(RefreshOutcome::IN_PROGRESS, $result->outcome);

        $this->fetcher->assertNothingFetched();
    }

    /**
     * A refreshing SAML connection of the tenant trusting the certificates,
     * with the attributes given.
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

            $masked = MaskedKey::fromCertificate($certificate);

            (new ConnectionKey)->forceFill([
                'connection_id' => $connection->id,
                'use'           => KeyUse::IDP_SIGNING,
                'state'         => null,
                'key_type'      => KeyType::RSA,
                'key_bits'      => 2048,
                'certificate'   => $masked->certificate,
                'public_key'    => $masked->publicKey,
                'private_key'   => null,
                'fingerprint'   => $masked->fingerprint,
            ])->save();
        }

        return $connection;
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
}
