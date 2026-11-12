<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\SamlMetadata;

use Illuminate\Console\Application as ConsoleApplication;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Configuration\ApplicationBuilder;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionSummary;
use SineMacula\Laravel\Sso\Console\RefreshMetadataCommand;
use SineMacula\Laravel\Sso\Keys\Enums\KeyStatus;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyResult;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\RefreshConnectionMetadata;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;

/**
 * The scheduled refresh examples of `docs/guides/saml-metadata.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataRefresher::class)]
#[CoversClass(RefreshMetadataCommand::class)]
#[CoversClass(RefreshConnectionMetadata::class)]
final class SamlMetadataScheduleExampleTest extends SamlMetadataExampleTestCase
{
    /** @var string The single sign-on URL the provider moves to. */
    private const string MOVED_SSO_URL = 'https://idp.example.com/saml/sso/v2';

    /** @var string What a run with `--sync` prints when it refreshed one connection. */
    private const string ONE_REFRESHED = 'Metadata refreshed: refreshed 1, failed 0, conflict 0, in_progress 0, rate_limited 0, skipped 0, refused 0';

    /** @var string What a run with `--sync` prints when its one refresh failed. */
    private const string ONE_FAILED = 'Metadata refreshed: refreshed 0, failed 1, conflict 0, in_progress 0, rate_limited 0, skipped 0, refused 0';

    /** @var string What a run with `--sync` prints when nothing was due. */
    private const string NOTHING_REFRESHED = 'Metadata refreshed: refreshed 0, failed 0, conflict 0, in_progress 0, rate_limited 0, skipped 0, refused 0';

    /** @var list<string> The environment variables the published queue reads. */
    private const array ENVIRONMENT = ['SSO_METADATA_QUEUE_CONNECTION', 'SSO_METADATA_QUEUE', 'SSO_METADATA_QUEUE_TIMEOUT_SECONDS', 'SSO_METADATA_QUEUE_TRIES'];

    /** @var \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The federation that signs the provider's metadata. */
    private FakeSamlIdentityProvider $federation;

    /**
     * Turn the scheduled refresh on and make the federation.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.features.metadata_refresh', true);

        $this->federation = new FakeSamlIdentityProvider('https://federation.example.com');
    }

    /**
     * Unset the variables a test set in the environment.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (self::ENVIRONMENT as $variable) {
            putenv($variable);
        }

        parent::tearDown();
    }

    /**
     * The guide's schedule runs the refresh every five minutes.
     *
     * @return void
     */
    public function testTheScheduleRunsTheRefreshEveryFiveMinutes(): void
    {
        /** @var \Closure(\Illuminate\Foundation\Configuration\ApplicationBuilder): \Illuminate\Foundation\Application $bootstrap */
        $bootstrap = require __DIR__ . '/bootstrap/app.php';

        $application = app();

        $bootstrap(new ApplicationBuilder($application));

        // Starting a console application runs what the builder wired to it
        new ConsoleApplication($application, $application->make(Dispatcher::class), $application->version());

        $expressions = [];

        foreach ($application->make(Schedule::class)->events() as $event) {
            if (Str::afterLast((string) $event->command, ' ') !== 'sso:metadata:refresh') {
                continue;
            }

            $expressions[] = $event->expression;
        }

        self::assertSame(['*/5 * * * *'], $expressions);
    }

    /**
     * A metadata URL and an anchor make the connection due at once, and a run
     * applies the signed metadata.
     *
     * @return void
     */
    public function testAUrlAndAnAnchorMakeTheConnectionFollowItsMetadata(): void
    {
        $this->serve($this->idp->metadata(self::MOVED_SSO_URL)->with(['sign' => 'entity'])->signedBy($this->federation->signer())->toXml());

        self::assertSame([], app(MetadataRefresher::class)->dueConnectionIds());

        [$updated, $anchored] = $this->follow();

        self::assertTrue($updated->isSucceeded());
        self::assertSame([KeyStatus::TRUSTED, KeyUse::METADATA_SIGNING], [$anchored->status, $anchored->key?->use]);
        self::assertSame([$this->connection->id], app(MetadataRefresher::class)->dueConnectionIds());

        self::assertSame(0, Artisan::call('sso:metadata:refresh', ['--sync' => true]));
        self::assertSame(self::ONE_REFRESHED, trim(Artisan::output()));
        self::assertSame(self::MOVED_SSO_URL, $this->stored()->settings['sso_url'] ?? null);
        self::assertSame([], app(MetadataRefresher::class)->dueConnectionIds());
    }

    /**
     * A metadata URL with no anchor and no opt-in refreshes nothing.
     *
     * @return void
     */
    public function testAUrlAloneRefreshesNothing(): void
    {
        self::assertTrue($this->withMetadataUrl()->isSucceeded());
        self::assertSame([], app(MetadataRefresher::class)->dueConnectionIds());

        self::assertSame(0, Artisan::call('sso:metadata:refresh', ['--sync' => true]));
        self::assertSame(self::NOTHING_REFRESHED, trim(Artisan::output()));
        $this->fetcher->assertNothingFetched();
    }

    /**
     * Metadata the anchor did not sign fails the refresh and changes nothing.
     *
     * @return void
     */
    public function testMetadataTheAnchorDidNotSignFails(): void
    {
        $this->serve($this->idp->metadata(self::MOVED_SSO_URL)->with(['sign' => 'entity'])->toXml());
        $this->follow();

        self::assertSame(0, Artisan::call('sso:metadata:refresh', ['--sync' => true]));
        self::assertSame(self::ONE_FAILED, trim(Artisan::output()));
        self::assertSame(self::SSO_URL, $this->stored()->settings['sso_url'] ?? null);
    }

    /**
     * Rows of `[environment, queue connection, queue]`.
     *
     * @return iterable<string, array{0: list<string>, 1: ?string, 2: ?string}>
     */
    public static function provideQueues(): iterable
    {
        yield from [
            'the defaults'    => [[], null, null],
            'the environment' => [['SSO_METADATA_QUEUE_CONNECTION=database', 'SSO_METADATA_QUEUE=metadata'], 'database', 'metadata'],
        ];
    }

    /**
     * A run queues each due refresh where the published configuration says.
     *
     * @param  list<string>  $environment
     * @param  ?string  $connection
     * @param  ?string  $queue
     * @return void
     */
    #[DataProvider('provideQueues')]
    public function testEachDueRefreshIsQueuedWhereThePublishedConfigurationSays(array $environment, ?string $connection, ?string $queue): void
    {
        foreach ($environment as $setting) {
            putenv($setting);
        }

        $this->publishConfiguration();
        $this->withMetadataUrl(['metadata_refresh' => true]);

        Bus::fake();

        self::assertSame(0, Artisan::call('sso:metadata:refresh'));
        self::assertSame('Metadata refreshes queued: 1', trim(Artisan::output()));

        $queued = [];

        Bus::assertDispatched(RefreshConnectionMetadata::class, static function (RefreshConnectionMetadata $job) use (&$queued): bool {
            $queued[] = [$job->connectionId, $job->connection, $job->queue, $job->timeout, $job->tries, $job->failOnTimeout];

            return true;
        });

        self::assertSame([[$this->connection->id, $connection, $queue, 60, 1, true]], $queued);
        $this->fetcher->assertNothingFetched();
    }

    /**
     * A timeout no shorter than the queue's `retry_after` (90 seconds) stops
     * the run.
     *
     * @return void
     */
    public function testATimeoutPastTheQueuesRetryAfterStopsTheRun(): void
    {
        putenv('SSO_METADATA_QUEUE_CONNECTION=database');
        putenv('SSO_METADATA_QUEUE_TIMEOUT_SECONDS=90');

        $this->publishConfiguration();
        $this->withMetadataUrl(['metadata_refresh' => true]);

        Bus::fake();

        self::assertSame(1, Artisan::call('sso:metadata:refresh'));
        self::assertSame('The metadata refresh stopped on InvalidArgumentException.', trim(Artisan::output()));
        Bus::assertNothingDispatched();
    }

    /**
     * Make a usable SAML connection with no metadata URL yet.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionSummary
     */
    #[\Override]
    protected function makeConnection(): ConnectionSummary
    {
        return $this->stored($this->makeSamlConnection($this->idp, ['sso_url' => self::SSO_URL]));
    }

    /**
     * Run the follow endpoint with the federation's certificate as anchor.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Connections\ConnectionResult, 1: \SineMacula\Laravel\Sso\Keys\KeyResult}
     */
    private function follow(): array
    {
        $results = self::atEndpoint('follow', [
            'tenant'     => $this->tenant,
            'connection' => $this->connection,
            'anchor'     => $this->federation->certificate(),
            'caller'     => self::caller(),
        ]);

        self::assertIsArray($results);
        self::assertInstanceOf(ConnectionResult::class, $results[0]);
        self::assertInstanceOf(KeyResult::class, $results[1]);

        return [$results[0], $results[1]];
    }

    /**
     * Lay the published metadata queue over the package's configuration.
     *
     * @return void
     */
    private function publishConfiguration(): void
    {
        /** @var array<string, mixed> $published */
        $published = require __DIR__ . '/config/sso.php';

        /** @var array<string, mixed> $package */
        $package = config('sso');

        config()->set('sso', array_replace_recursive($package, $published));
    }
}
