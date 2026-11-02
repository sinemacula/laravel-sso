<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
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
 * in the due listing), counts an administrator's refresh against the
 * connection's metadata limit (the counter's conditional update and its
 * insert-unless-exists, two writes on a fresh window), reads its anchors and
 * its trusted certificates (the claim's snapshot), and claims it with one
 * conditional update that writes the claim's token; after, in one transaction,
 * it reads the connection locked and its certificates and anchors locked in one
 * statement, compares them with the snapshot, and writes only what changed:
 *
 * - a refresh now that adds a certificate: 7 reads (the connection, the anchors
 *   and the certificates; the connection and the snapshot's fingerprints
 *   locked; the certificates locked to replace them; the fingerprints judged
 *   before the insert) and 5 writes (the counter's two, the claim, the insert,
 *   the connection's refresh);
 * - a refresh now that removes a certificate and moves the endpoint: 6 reads
 *   and 8 writes (the counter's two, the claim, the delete, the requests and
 *   the handoff codes voided, the trust version raised once, the connection's
 *   settings and refresh in one update);
 * - a scheduled refresh of one connection that changes nothing: 6 reads (the
 *   listing, the anchors, the certificates, then the three locked reads) and 2
 *   writes (the claim, the refresh), the schedule counting nothing;
 * - a failed refresh: 5 reads (the connection, the anchors, the certificates,
 *   the connection and the fingerprints locked) and 4 writes (the counter's
 *   two, the claim, the failure);
 * - a refresh now whose claim another server holds: 3 reads, the counter's two
 *   writes and the claim's update, which changes no row;
 * - a refresh now past the metadata limit: 2 reads (the connection, then the
 *   full counter for its wait) and the counter's 3 writes (its conditional
 *   update, its insert-unless-exists and the update tried again), none of which
 *   changes a row; nothing is claimed or fetched.
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
     * A refresh now that adds a certificate is seven reads and five writes.
     *
     * @return void
     */
    public function testARefreshAddingACertificateIsSevenReadsAndFiveWrites(): void
    {
        $connection = $this->saml([self::idp()->certificate()]);

        $this->serve(self::idp()->metadata()->with(['signing_certificates' => [self::idp()->certificate(), Certificates::distinct(0)]]));

        $result = $this->assertQueryBudget(7, 5, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor()));

        self::assertSame([RefreshOutcome::REFRESHED, ['idp_signing_certificates'], false], [$result->outcome, $result->changedSettings, $result->trustChanged]);
    }

    /**
     * A refresh now that removes a certificate and moves the endpoint is six
     * reads and eight writes, the trust version raised once.
     *
     * @return void
     */
    public function testARefreshRemovingACertificateAndMovingTheEndpointIsSixReadsAndEightWrites(): void
    {
        $connection = $this->saml([self::idp()->certificate(), Certificates::distinct(0)]);

        $this->serve(self::idp()->metadata('https://login.example.test/saml/sso'));

        $result = $this->assertQueryBudget(6, 8, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor()));

        self::assertSame([RefreshOutcome::REFRESHED, ['sso_url', 'idp_signing_certificates'], true], [$result->outcome, $result->changedSettings, $result->trustChanged]);
    }

    /**
     * A scheduled refresh of one connection that changes nothing is six reads
     * and two writes.
     *
     * @return void
     */
    public function testAScheduledRefreshChangingNothingIsSixReadsAndTwoWrites(): void
    {
        $this->saml([self::idp()->certificate()]);
        $this->serve(self::idp()->metadata());

        $results = $this->assertQueryBudget(6, 2, fn (): array => $this->refresher()->refreshDue());

        self::assertSame([RefreshOutcome::REFRESHED], array_map(static fn (RefreshResult $result): RefreshOutcome => $result->outcome, $results));
    }

    /**
     * A failed refresh is five reads and four writes.
     *
     * @return void
     */
    public function testAFailedRefreshIsFiveReadsAndFourWrites(): void
    {
        $connection = $this->saml([self::idp()->certificate()]);

        $this->fetcher->respond(self::URL, FetchResult::failed());

        $result = $this->assertQueryBudget(5, 4, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor()));

        self::assertSame(RefreshOutcome::FAILED, $result->outcome);
    }

    /**
     * A refresh now whose claim another server holds is three reads, the
     * counter's two writes and the claim's update, and fetches nothing.
     *
     * @return void
     */
    public function testARefreshWhoseClaimIsHeldIsThreeReadsAndThreeWrites(): void
    {
        $connection = $this->saml([self::idp()->certificate()], ['metadata_claimed_until' => $this->clock->now()->addMinute()]);

        $result = $this->assertQueryBudget(3, 3, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor()));

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

        $connection = $this->saml([self::idp()->certificate()], ['metadata_claimed_until' => $this->clock->now()->addMinute()]);

        $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor());

        $result = $this->assertQueryBudget(2, 3, fn (): RefreshResult => $this->refresher()->refreshNow(self::TENANT, $connection->id, self::actor()));

        self::assertSame(RefreshOutcome::RATE_LIMITED, $result->outcome);

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
