<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Console\RefreshMetadataCommand;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Database\StorageConnection;
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
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for `sso:metadata:refresh`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshMetadataCommand::class)]
#[CoversClass(RefreshConnectionMetadata::class)]
final class RefreshMetadataCommandTest extends TestCase
{
    use UsesConnections;

    /** @var string The summary of a run that refreshed nothing. */
    private const string NOTHING = 'Metadata refreshed: refreshed 0, failed 0, conflict 0, in_progress 0, rate_limited 0, skipped 0, refused 0';

    /** @var string The URL the working provider serves its metadata at. */
    private const string URL = 'https://idp.example.test/metadata.xml';

    /** @var string The URL the failing provider serves nothing at. */
    private const string FAILING_URL = 'https://down.example.test/metadata.xml';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the refresh fetches through. */
    private FakeFetcher $fetcher;

    /**
     * Bind a fixed clock and a fake fetcher, enable SAML and the refresh, and
     * create the tables.
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
        config()->set('sso.features.metadata_refresh', true);

        $this->usePackageTables();
    }

    /**
     * With nothing due, the run queues nothing and passes.
     *
     * @return void
     */
    public function testWithNothingDueQueuesNothing(): void
    {
        Bus::fake();

        self::assertSame([0, ['Metadata refreshes queued: 0']], $this->refreshFromConsole());
        self::assertSame([0, [self::NOTHING]], $this->refreshFromConsole(true));

        Bus::assertNothingDispatched();
    }

    /**
     * Each due connection is queued as one job with the configured queue and
     * options.
     *
     * @return void
     */
    public function testQueuesOneJobPerDueConnection(): void
    {
        Bus::fake();

        config()->set('queue.connections.metadata', ['driver' => 'sync']);
        config()->set('sso.metadata.queue', ['connection' => 'metadata', 'name' => 'slow', 'timeout_seconds' => 240, 'tries' => 2]);

        $one = $this->saml(self::URL);
        $two = $this->saml(self::FAILING_URL);

        [$code, $output] = $this->refreshFromConsole();

        self::assertSame([0, ['Metadata refreshes queued: 2']], [$code, $output]);
        $this->fetcher->assertNothingFetched();

        $queued = [];

        Bus::assertDispatched(RefreshConnectionMetadata::class, static function (RefreshConnectionMetadata $job) use (&$queued): bool {
            $queued[] = [$job->connectionId, $job->connection, $job->queue, $job->timeout, $job->tries, $job->failOnTimeout];

            return true;
        });

        $expected = [[$one->id, 'metadata', 'slow', 240, 2, true], [$two->id, 'metadata', 'slow', 240, 2, true]];

        sort($queued);
        sort($expected);

        self::assertSame($expected, $queued);
    }

    /**
     * A job with no queue configured takes the defaults and serialises only the
     * id.
     *
     * @return void
     */
    public function testAJobTakesTheDefaultQueueAndOptions(): void
    {
        $job = new RefreshConnectionMetadata('01jbz0000000000000000000zz', app(MetadataSettings::class));

        $options = [$job->connectionId, $job->connection, $job->queue, $job->timeout, $job->tries, $job->failOnTimeout];
        $copy    = unserialize(serialize($job));

        self::assertSame(['01jbz0000000000000000000zz', null, null, 60, 1, true], $options);
        self::assertStringNotContainsString('MetadataSettings', serialize($job));
        self::assertInstanceOf(RefreshConnectionMetadata::class, $copy);
        self::assertSame('01jbz0000000000000000000zz', $copy->connectionId);
    }

    /**
     * A queued job refreshes its connection only while it is due.
     *
     * @return void
     */
    public function testAQueuedJobRefreshesItsConnectionWhileItIsDue(): void
    {
        $connection = $this->saml(self::URL);

        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], self::idp()->metadata()->toXml()));

        $job = new RefreshConnectionMetadata($connection->id, app(MetadataSettings::class));

        $job->handle(app(MetadataRefresher::class));

        self::assertSame(1, Connection::query()->findOrFail($connection->id)->metadata_version);

        $job->handle(app(MetadataRefresher::class));
        (new RefreshConnectionMetadata('01jbz0000000000000000000zz', app(MetadataSettings::class)))->handle(app(MetadataRefresher::class));

        self::assertSame(1, Connection::query()->findOrFail($connection->id)->metadata_version);
        self::assertCount(1, $this->fetcher->requests());
    }

    /**
     * `--sync` counts each outcome, prints no connection values and queues
     * nothing.
     *
     * @return void
     */
    public function testSyncRefreshesInlineCountingEachOutcomeAndPrintsNoValue(): void
    {
        Bus::fake();

        $this->saml(self::URL);
        $this->saml(self::FAILING_URL);

        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], self::idp()->metadata()->toXml()));
        $this->fetcher->respond(self::FAILING_URL, FetchResult::failed());

        [$code, $output] = $this->refreshFromConsole(true);

        self::assertSame([0, ['Metadata refreshed: refreshed 1, failed 1, conflict 0, in_progress 0, rate_limited 0, skipped 0, refused 0']], [$code, $output]);

        foreach ([self::URL, self::FAILING_URL, FakeSamlIdentityProvider::ENTITY_ID, FakeSamlIdentityProvider::SSO_URL] as $value) {
            self::assertStringNotContainsString($value, implode("\n", $output));
        }

        self::assertSame([0, [self::NOTHING]], $this->refreshFromConsole(true));
        self::assertCount(2, $this->fetcher->requests());

        Bus::assertNothingDispatched();
    }

    /**
     * `--sync` records a malformed aggregate's failure and goes on.
     *
     * @return void
     */
    public function testSyncGoesOnPastMalformedMetadata(): void
    {
        $malformed = $this->saml(self::FAILING_URL, '01jb0000000000000000000001');
        $working   = $this->saml(self::URL, '01jb0000000000000000000002');
        $aggregate = self::idp()->metadata()->with(['aggregate' => ['https://other.example.test/saml']])->toXml();

        $this->fetcher->respond(self::FAILING_URL, FetchResult::fetched(200, [], str_replace('ID="_aggregate"', 'ID="_aggregate" validUntil="2026-13-01T00:00:00Z"', $aggregate)));
        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], self::idp()->metadata()->toXml()));

        [$code, $output] = $this->refreshFromConsole(true);

        $failed    = Connection::query()->findOrFail($malformed->id);
        $refreshed = Connection::query()->findOrFail($working->id);

        self::assertSame([0, ['Metadata refreshed: refreshed 1, failed 1, conflict 0, in_progress 0, rate_limited 0, skipped 0, refused 0']], [$code, $output]);
        self::assertSame([0, 1, '2026-11-01T09:35:00+00:00'], [$failed->metadata_version, $failed->metadata_refresh_failures, $failed->metadata_refresh_at?->toIso8601String()]);
        self::assertSame([null, null], [$failed->metadata_claimed_until, $failed->metadata_claim_token]);
        self::assertSame([1, 0], [$refreshed->metadata_version, $refreshed->metadata_refresh_failures]);
        self::assertCount(2, $this->fetcher->requests());
    }

    /**
     * Rows of `[sync]`: queued and inline.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideModes(): iterable
    {
        yield from [
            'queued' => [false],
            'inline' => [true],
        ];
    }

    /**
     * A run that stopped exits 1 naming the exception's class alone.
     *
     * @param  bool  $sync
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testARunThatStoppedNamesTheExceptionsClassAlone(bool $sync): void
    {
        Bus::fake();

        $this->saml(self::URL);

        $result = DB::connection(StorageConnection::name())->transaction(fn (): array => $this->refreshFromConsole($sync));

        self::assertSame([1, ['The metadata refresh stopped on LogicException.']], $result);

        $this->fetcher->assertNothingFetched();
        Bus::assertNothingDispatched();
    }

    /**
     * Run the command, with `--sync` when asked, and answer its exit code and
     * non-empty lines.
     *
     * @param  bool  $sync
     * @return array{0: int, 1: list<string>}
     */
    private function refreshFromConsole(bool $sync = false): array
    {
        $code   = Artisan::call('sso:metadata:refresh', $sync ? ['--sync' => true] : []);
        $output = array_values(array_filter(explode("\n", Artisan::output()), static fn (string $line): bool => trim($line) !== ''));

        return [$code, array_map(trim(...), $output)];
    }

    /**
     * A refreshing SAML connection fetching from the URL and trusting the
     * provider.
     *
     * @param  string  $url
     * @param  ?string  $id
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(string $url, ?string $id = null): Connection
    {
        $connection = $this->makeConnection([...($id === null ? [] : ['id' => $id]), 'protocol' => 'saml2', 'enabled' => true, 'settings' => [
            'idp_entity_id'    => FakeSamlIdentityProvider::ENTITY_ID,
            'sso_url'          => FakeSamlIdentityProvider::SSO_URL,
            'sso_binding'      => 'http_redirect',
            'metadata_url'     => $url,
            'metadata_refresh' => true,
        ]]);

        $masked = MaskedKey::fromCertificate(self::idp()->certificate());

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

        return $connection;
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
