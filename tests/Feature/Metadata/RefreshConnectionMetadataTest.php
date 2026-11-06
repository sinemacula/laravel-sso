<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\MetadataRefreshed;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\MetadataSettings;
use SineMacula\Laravel\Sso\Metadata\RefreshConnectionMetadata;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the queued refresh of one connection's metadata: the job
 * hands its connection's id to the refresher, which refreshes it for no client,
 * so what the refresh reports carries no IP address and no user agent, even
 * while a request is bound; and a job whose connection is gone refreshes
 * nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshConnectionMetadata::class)]
final class RefreshConnectionMetadataTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /** @var string The URL the SAML provider serves its metadata at. */
    private const string URL = 'https://idp.example.test/metadata.xml';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The SAML provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the provider answers on. */
    private FakeFetcher $fetcher;

    /**
     * Bind a fixed clock and a fake fetcher serving the provider's metadata,
     * switch SAML and the refresh on, create the tables, and bind a request the
     * refresh must never read.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher = new FakeFetcher;

        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], self::idp()->metadata()->toXml()));

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Fetcher::class, $this->fetcher);
        $this->app?->instance('request', Request::create('/', 'POST', server: ['REMOTE_ADDR' => '198.51.100.9', 'HTTP_USER_AGENT' => 'Served/1.0']));

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.metadata_refresh', true);

        $this->usePackageTables();
    }

    /**
     * The job refreshes its connection, and every event the refresh reports
     * carries no client.
     *
     * @return void
     */
    public function testTheJobRefreshesItsConnectionForNoClient(): void
    {
        $connection = $this->saml();

        $this->startRecordingEvents();

        self::job($connection->id)->handle(app(MetadataRefresher::class));

        self::assertSame(1, Connection::query()->findOrFail($connection->id)->metadata_version);
        self::assertContains(MetadataRefreshed::class, array_map(static fn (SsoEvent $event): string => $event::class, $this->recordedEvents()));

        foreach ($this->recordedEvents() as $event) {
            self::assertSame([null, null], [$event->context()->ip, $event->context()->userAgent], $event::class);
        }
    }

    /**
     * A job whose connection is gone fetches and reports nothing.
     *
     * @return void
     */
    public function testAJobWhoseConnectionIsGoneDoesNothing(): void
    {
        $this->startRecordingEvents();

        self::job('01jbunknownconnection00000')->handle(app(MetadataRefresher::class));

        $this->fetcher->assertNothingFetched();
        $this->assertNoEvents();
    }

    /**
     * The job for the connection, with the queue options configured.
     *
     * @param  string  $connectionId
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshConnectionMetadata
     */
    private static function job(string $connectionId): RefreshConnectionMetadata
    {
        return new RefreshConnectionMetadata($connectionId, app(MetadataSettings::class));
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
     * The SAML provider, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }
}
