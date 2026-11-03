<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\SamlMetadata;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionSummary;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\RefreshResult;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;

/**
 * The administrator's refresh example of `docs/guides/saml-metadata.md`
 * (SSO-2.8, SSO-11.12, SSO-12.5), on the shared example harness, with the
 * application's own tenant: the refresh endpoint applies a provider's rotated
 * certificate and moved sign-on URL at once to a connection that has a metadata
 * URL but has not opted in, asking for its trust, and the schedule goes on
 * leaving it alone; a refresh past the connection's metadata limit goes back
 * with the wait, and a stale administrator is refused with
 * `freshness_required`, fetching nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataRefresher::class)]
#[CoversClass(RefreshResult::class)]
final class SamlMetadataRefreshNowExampleTest extends SamlMetadataExampleTestCase
{
    /** @var string The single sign-on URL the provider moves to. */
    private const string MOVED_SSO_URL = 'https://idp.example.com/saml/sso/v2';

    /**
     * Turn the scheduled refresh on, and give the tenant's connection the
     * guide's metadata URL and no anchor.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.features.metadata_refresh', true);

        self::assertTrue($this->withMetadataUrl()->isSucceeded());
    }

    /**
     * An administrator's refresh asks for the connection's trust, since the
     * schedule leaves it alone, and applies the provider's rotated certificate
     * and moved sign-on URL at once; the schedule goes on leaving it alone.
     *
     * @return void
     */
    public function testAnAdministratorRefreshesAConnectionAtOnce(): void
    {
        $rotated = new FakeSamlIdentityProvider(self::ENTITY_ID);

        $this->serve($rotated->metadata(self::MOVED_SSO_URL)->toXml());
        $freshness = FakeFreshness::fresh();
        $this->instance(Freshness::class, $freshness);

        $shown = $this->refreshNow();

        self::assertIsArray($shown);
        self::assertSame(RefreshOutcome::REFRESHED, $shown['outcome']);
        self::assertSame(['sso_url', 'idp_signing_certificates'], $shown['changed']);
        $freshness->assertAsked(FreshnessOperation::CONNECTION_TRUST);

        self::assertSame(self::MOVED_SSO_URL, $this->stored()->settings['sso_url'] ?? null);
        self::assertSame([openssl_x509_fingerprint($rotated->certificate(), 'sha256')], $this->trustedFingerprints());
        self::assertSame([], app(MetadataRefresher::class)->dueConnectionIds());
    }

    /**
     * A refresh past the connection's metadata limit goes back with the seconds
     * until its window ends, having fetched nothing.
     *
     * @return void
     */
    public function testARefreshPastTheLimitGoesBackWithTheWait(): void
    {
        config()->set('sso.rate_limits.metadata.per_connection', ['max' => 1, 'decay_seconds' => 3600]);

        $this->serve($this->idp->metadata(self::SSO_URL)->toXml());

        self::assertIsArray($this->refreshNow());
        self::assertCount(1, $this->fetcher->requests());

        self::assertSame(['metadata' => ['Try again in 1800 seconds.']], self::errors($this->refreshNow()));
        self::assertCount(1, $this->fetcher->requests());
    }

    /**
     * An administrator who has not authenticated recently enough cannot refresh
     * a connection the schedule leaves alone: the refresh is refused with
     * `freshness_required`, and nothing is fetched.
     *
     * @return void
     */
    public function testAStaleAdministratorCannotRefreshWhatTheScheduleLeavesAlone(): void
    {
        $this->freshness->staleFor(FreshnessOperation::CONNECTION_TRUST);

        $shown = $this->refreshNow();

        self::assertIsArray($shown);
        self::assertSame(RefreshOutcome::REFUSED, $shown['outcome']);
        self::assertInstanceOf(RefreshResult::class, $shown['result']);
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $shown['result']->reason);
        $this->fetcher->assertNothingFetched();
    }

    /**
     * Make the tenant's usable SAML connection, trusting the provider's
     * certificate.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionSummary
     */
    #[\Override]
    protected function makeConnection(): ConnectionSummary
    {
        return $this->stored($this->makeSamlConnection($this->idp, ['sso_url' => self::SSO_URL]));
    }

    /**
     * Run the refresh endpoint for the connection as the administrator, and
     * answer what it answers.
     *
     * @return mixed
     */
    private function refreshNow(): mixed
    {
        return self::atEndpoint('refresh', ['tenant' => $this->tenant, 'connection' => $this->connection, 'actor' => self::actor()]);
    }
}
