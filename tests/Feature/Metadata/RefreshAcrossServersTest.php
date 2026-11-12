<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Bus;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Console\RefreshMetadataCommand;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\MetadataSources;
use SineMacula\Laravel\Sso\Metadata\RefreshConnectionMetadata;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for `sso:metadata:refresh` across servers, beyond the
 * concurrency suites.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshMetadataCommand::class)]
#[CoversClass(MetadataRefresher::class)]
#[CoversClass(RefreshConnectionMetadata::class)]
final class RefreshAcrossServersTest extends TestCase
{
    use UsesConnections;

    /** @var string The URL the SAML provider serves its metadata at. */
    private const string URL = 'https://idp.example.test/metadata.xml';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The SAML provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The OIDC provider's key, generated once. */
    private static ?FakeSigningKey $key = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher both providers answer on. */
    private FakeFetcher $fetcher;

    /**
     * Bind a fixed clock and a fetcher serving both providers, enable both
     * protocols and refresh, and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock   = new FixedClock('2026-11-01T09:30:00Z');
        $this->fetcher = new FakeFetcher;

        (new FakeOpenIdProvider(FakeOpenIdProvider::ISSUER, self::key()))->serve($this->fetcher);

        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], self::idp()->metadata()->toXml()));

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Fetcher::class, $this->fetcher);

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.oidc', true);
        config()->set('sso.features.metadata_refresh', true);

        $this->usePackageTables();
    }

    /**
     * Overlapping commands queue duplicate jobs; the first refreshes once and
     * the rest are `skipped`.
     *
     * @return void
     */
    public function testDuplicateQueuedJobsApplyOnce(): void
    {
        Bus::fake();

        $saml = $this->saml();
        $oidc = $this->oidc();

        self::assertSame(0, Artisan::call('sso:metadata:refresh'));
        self::assertSame('Metadata refreshes queued: 2', trim(Artisan::output()));
        self::assertSame(0, Artisan::call('sso:metadata:refresh'));
        self::assertSame('Metadata refreshes queued: 2', trim(Artisan::output()));

        $jobs = [];

        Bus::assertDispatched(RefreshConnectionMetadata::class, static function (RefreshConnectionMetadata $job) use (&$jobs): bool {
            $jobs[] = $job->connectionId;

            return true;
        });

        self::assertCount(4, $jobs);

        $this->fetcher->assertNothingFetched();

        $outcomes = [];

        foreach ($jobs as $id) {
            $outcomes[$id][] = $this->refresher()->refreshQueued($id, Clients::browser())->outcome;
        }

        foreach ([$saml, $oidc] as $connection) {
            self::assertSame([RefreshOutcome::REFRESHED, RefreshOutcome::SKIPPED], $outcomes[$connection->id]);
            self::assertSame(1, Connection::query()->findOrFail($connection->id)->metadata_version);
            self::assertNull(Connection::query()->findOrFail($connection->id)->metadata_claim_token);
        }

        // The SAML document once, and the OIDC document and keys once each
        self::assertCount(3, $this->fetcher->requests());
    }

    /**
     * A second `--sync` run over what a first refreshed does nothing.
     *
     * @return void
     */
    public function testASecondSyncRunDoesNothing(): void
    {
        $this->saml();
        $this->oidc();

        self::assertSame(0, Artisan::call('sso:metadata:refresh', ['--sync' => true]));
        self::assertStringContainsString('refreshed 2,', Artisan::output());

        $fetched = count($this->fetcher->requests());

        self::assertSame(0, Artisan::call('sso:metadata:refresh', ['--sync' => true]));
        self::assertStringContainsString('refreshed 0, failed 0, conflict 0, in_progress 0, rate_limited 0, skipped 0, refused 0', Artisan::output());
        self::assertCount($fetched, $this->fetcher->requests());
    }

    /**
     * Rows of `[protocol]`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideProtocols(): iterable
    {
        yield 'SAML' => ['saml2'];
        yield 'OIDC' => ['oidc'];
    }

    /**
     * A dead worker's claim holds its connection until it runs out, to the
     * second, then it is taken over.
     *
     * @param  string  $protocol
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideProtocols')]
    public function testAWorkerThatDiedHoldsItsConnectionUntilTheClaimRunsOut(string $protocol): void
    {
        $connection = $protocol === 'saml2' ? $this->saml() : $this->oidc();
        $dead       = app(MetadataSources::class)->for($protocol)?->claim(Connection::query()->findOrFail($connection->id));

        self::assertNotNull($dead);

        self::assertSame([], $this->refresher()->dueConnectionIds());
        self::assertSame(RefreshOutcome::SKIPPED, $this->refresher()->refreshQueued($connection->id, Clients::browser())->outcome);

        $this->clock->advance(299);

        self::assertSame([], $this->refresher()->dueConnectionIds());
        self::assertSame(RefreshOutcome::SKIPPED, $this->refresher()->refreshQueued($connection->id, Clients::browser())->outcome);

        $this->fetcher->assertNothingFetched();

        $this->clock->advance(1);

        self::assertSame([$connection->id], $this->refresher()->dueConnectionIds());
        self::assertSame(RefreshOutcome::REFRESHED, $this->refresher()->refreshQueued($connection->id, Clients::browser())->outcome);

        $row = Connection::query()->findOrFail($connection->id);

        self::assertSame(1, $row->metadata_version);
        self::assertNull($row->metadata_claim_token);
        self::assertNull($row->metadata_claimed_until);
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
     * A refreshing SAML connection trusting the provider's certificate.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(): Connection
    {
        $connection = $this->makeConnection(['protocol' => 'saml2', 'enabled' => true, 'settings' => [
            'idp_entity_id'    => FakeSamlIdentityProvider::ENTITY_ID,
            'sso_url'          => FakeSamlIdentityProvider::SSO_URL,
            'sso_binding'      => 'http_redirect',
            'metadata_url'     => self::URL,
            'metadata_refresh' => true,
        ]]);

        $masked = MaskedKey::fromCertificate(self::idp()->certificate());

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $masked->certificate,
            'public_key'    => $masked->publicKey,
            'fingerprint'   => $masked->fingerprint,
        ])->save();

        return $connection;
    }

    /**
     * A refreshing OIDC connection pinned to the provider's issuer.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function oidc(): Connection
    {
        return $this->makeConnection(['protocol' => 'oidc', 'enabled' => true, 'settings' => [
            'issuer'           => FakeOpenIdProvider::ISSUER,
            'metadata_refresh' => true,
        ]]);
    }

    /**
     * The SAML provider, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }

    /**
     * The OIDC provider's key, generated once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(): FakeSigningKey
    {
        return self::$key ??= FakeSigningKey::rsa();
    }
}
