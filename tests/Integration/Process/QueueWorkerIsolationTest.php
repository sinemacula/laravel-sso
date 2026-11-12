<?php

declare(strict_types = 1);

namespace Tests\Integration\Process;

use Illuminate\Contracts\Bus\Dispatcher;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\MetadataSettings;
use SineMacula\Laravel\Sso\Metadata\RefreshConnectionMetadata;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use Tests\Concerns\FailsDatabaseStatements;
use Tests\Concerns\FlowRoutes;
use Tests\Concerns\RunsLongLivedApplication;
use Tests\Fixtures\Queue\RecordsItsRun;
use Tests\Fixtures\Queue\ScopedEndpoints;
use Tests\TestCase;

/**
 * Integration tests for one queue worker running jobs for different
 * connections.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshConnectionMetadata::class)]
#[CoversClass(MetadataRefresher::class)]
#[CoversClass(ProtocolManager::class)]
final class QueueWorkerIsolationTest extends TestCase
{
    use FailsDatabaseStatements, FlowRoutes, RunsLongLivedApplication;

    /** @var string The tenant of the SAML connection. */
    private const string TENANT_A = 'tenant-alpha-queue';

    /** @var string The tenant of the OIDC connection. */
    private const string TENANT_B = 'tenant-bravo-queue';

    /** @var string The host of the SAML provider. */
    private const string HOST_A = 'idp-queue';

    /** @var string The URL the SAML provider serves its metadata at. */
    private const string METADATA_URL = 'https://idp-queue.example.test/metadata.xml';

    /** @var string The OIDC provider's issuer. */
    private const string ISSUER_B = 'https://op-queue.example.test';

    /** @var \SineMacula\Laravel\Sso\Models\Connection A refreshing SAML connection. */
    private Connection $connectionA;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A refreshing OIDC connection. */
    private Connection $connectionB;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The OIDC provider. */
    private FakeOpenIdProvider $providerB;

    /**
     * Create the queue and two tenants' connections, each with its own
     * provider.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->prepareFlows();
        $this->usePackageTables();
        $this->createWorkerQueue();

        config()->set('sso.features.metadata_refresh', true);
        config()->set('sso.metadata.queue', ['connection' => self::$workerQueueConnection, 'name' => null, 'timeout_seconds' => 30, 'tries' => 1]);

        $this->connectionA = $this->flowSamlConnection(self::TENANT_A, self::HOST_A, ['metadata_url' => self::METADATA_URL, 'metadata_refresh' => true]);

        $this->serveFlowDocument(self::METADATA_URL, self::flowIdp(self::HOST_A)->metadata('https://' . self::HOST_A . '.example.test/saml/sso')->toXml());

        $this->providerB   = $this->servedFlowProvider(self::ISSUER_B, self::flowKey('op-queue'));
        $this->connectionB = $this->makeConnection(['tenant_id' => self::TENANT_B, 'enabled' => true, 'settings' => ['issuer' => self::ISSUER_B, 'metadata_refresh' => true]]);

        RecordsItsRun::$runs = [];
    }

    /**
     * Drop the queue.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropWorkerQueue();

        parent::tearDown();
    }

    /**
     * A, B, then A each refresh only the connection they name, and nothing
     * stays.
     *
     * @return void
     */
    public function testEachJobRefreshesOnlyItsOwnConnection(): void
    {
        $this->queueRefresh($this->connectionA);
        $this->queueRefresh($this->connectionB);
        $this->queueRefresh($this->connectionA);

        self::assertSame(3, $this->jobsWaiting());

        $this->workNextJob();

        self::assertSame([1, 0], [$this->versionOf($this->connectionA), $this->versionOf($this->connectionB)]);
        self::assertSame([self::METADATA_URL], $this->fetchedUrls());
        $this->assertNothingOfEitherStays();

        $this->workNextJob();

        self::assertSame([1, 1], [$this->versionOf($this->connectionA), $this->versionOf($this->connectionB)]);
        self::assertSame([self::METADATA_URL, $this->providerB->discoveryUrl(), $this->providerB->endpoint('jwks')], $this->fetchedUrls());
        $this->assertNothingOfEitherStays();

        $this->workNextJob();

        self::assertSame([1, 1], [$this->versionOf($this->connectionA), $this->versionOf($this->connectionB)]);
        self::assertCount(3, $this->fetchedUrls());
        self::assertSame(0, $this->jobsWaiting());
        $this->assertNothingOfEitherStays();
    }

    /**
     * The worker forgets scoped services between jobs and keeps singletons.
     *
     * @return void
     */
    public function testEachJobFindsTheScopedServicesForgotten(): void
    {
        $this->queueRefresh($this->connectionA);
        $this->queueRefresh($this->connectionB);

        $scoped = self::scopedServices();
        $clock  = app(Clock::class);

        $this->workNextJob();

        $afterA = self::scopedServices();

        foreach ($scoped as $service => $instance) {
            self::assertNotSame($instance, $afterA[$service], "{$service} stayed across the worker's reset.");
        }

        self::assertSame([1, 0], [$this->versionOf($this->connectionA), $this->versionOf($this->connectionB)]);

        $this->workNextJob();

        foreach (self::scopedServices() as $service => $instance) {
            self::assertNotSame($afterA[$service], $instance, "{$service} stayed across the worker's reset.");
        }

        self::assertSame([1, 1], [$this->versionOf($this->connectionA), $this->versionOf($this->connectionB)]);
        self::assertSame($clock, app(Clock::class));
    }

    /**
     * The registry keeps a driver for one job's scope only.
     *
     * @return void
     */
    public function testADriverIsBuiltAnewWithEachJobsScope(): void
    {
        $protocols = app(ProtocolManager::class);
        $saml      = $protocols->protocol('saml2');
        $oidc      = $protocols->protocol('oidc');

        self::assertSame($saml, $protocols->protocol('saml2'));

        dispatch(new RecordsItsRun('next'));

        $this->workNextJob();

        self::assertSame(['next'], RecordsItsRun::$runs);
        self::assertNotSame($saml, $protocols->protocol('saml2'));
        self::assertNotSame($oidc, $protocols->protocol('oidc'));
        self::assertSame($protocols->protocol('saml2'), $protocols->protocol('saml2'));
    }

    /**
     * A driver uses the current job's endpoint resolver.
     *
     * @return void
     */
    public function testAnApplicationsScopedServiceIsThatOfTheJobServed(): void
    {
        $scope = 0;

        $this->app?->scoped(EndpointResolver::class, static function () use (&$scope): EndpointResolver {
            $scope++;

            return new ScopedEndpoints("scope-{$scope}.example.test");
        });

        $describe = fn (): string => (string) app(ServiceProviderDescriptions::class)->describe(self::TENANT_A, $this->connectionA->id)->body;

        self::assertStringContainsString('scope-1.example.test', $describe());

        dispatch(new RecordsItsRun('next'));

        $this->workNextJob();

        $answer = $describe();

        self::assertStringContainsString('scope-2.example.test', $answer);
        self::assertStringNotContainsString('scope-1.example.test', $answer);
    }

    /**
     * Once due again, the third job refreshes from its own provider.
     *
     * @return void
     */
    public function testAConnectionDueAgainIsRefreshedFromItsOwnProvider(): void
    {
        $this->queueRefresh($this->connectionA);
        $this->queueRefresh($this->connectionB);

        $this->workNextJob();
        $this->workNextJob();

        Connection::query()->useWritePdo()->whereKey($this->connectionA->id)->update(['metadata_refresh_at' => null]);

        $this->queueRefresh($this->connectionA);

        $this->workNextJob();

        $urls = $this->fetchedUrls();

        self::assertSame(self::METADATA_URL, end($urls));
        self::assertCount(2, array_keys($urls, self::METADATA_URL, true));
        self::assertNull(Connection::query()->useWritePdo()->findOrFail($this->connectionA->id)->metadata_claim_token);
    }

    /**
     * An application job that throws is recorded and the next job runs.
     *
     * @return void
     */
    public function testAJobThatThrowsDoesNotStopTheNext(): void
    {
        $this->queueRefresh($this->connectionA);

        dispatch(new RecordsItsRun('throw'));

        $this->queueRefresh($this->connectionB);

        $this->workNextJob();
        $this->workNextJob();
        $this->workNextJob();

        self::assertSame(['throw'], RecordsItsRun::$runs);
        self::assertSame(0, $this->jobsWaiting());
        self::assertSame([1, 1], [$this->versionOf($this->connectionA), $this->versionOf($this->connectionB)]);
        $this->assertNothingOfEitherStays();
    }

    /**
     * A refresh whose claim fails leaves its connection unclaimed and the
     * worker clean.
     *
     * @return void
     */
    public function testAJobOnAFailedStatementFailsAloneAndCanRunAgain(): void
    {
        $this->queueRefresh($this->connectionA);
        $this->queueRefresh($this->connectionB);

        $this->failStatement(self::onTable('update', StorageConnection::table('connections.table')));

        $this->workNextJob();

        self::assertSame(1, $this->databaseFailuresFired());
        self::assertSame(0, $this->versionOf($this->connectionA));
        self::assertNull(Connection::query()->useWritePdo()->findOrFail($this->connectionA->id)->metadata_claim_token);
        self::assertSame([], $this->fetchedUrls());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());

        $this->workNextJob();

        self::assertSame(1, $this->versionOf($this->connectionB));
        self::assertSame(0, $this->jobsWaiting());

        $this->queueRefresh($this->connectionA);

        $this->workNextJob();

        self::assertSame(1, $this->versionOf($this->connectionA));
    }

    /**
     * The metadata refresh is the only job the package queues.
     *
     * @return void
     */
    public function testTheOneQueuedClassIsTheMetadataRefresh(): void
    {
        $root  = dirname(__DIR__, 3) . '/';
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . 'src', \FilesystemIterator::SKIP_DOTS));
        $found = [];

        foreach ($files as $file) {

            if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'php' || !str_contains((string) file_get_contents($file->getPathname()), 'ShouldQueue')) {
                continue;
            }

            $found[] = substr($file->getPathname(), strlen($root));
        }

        self::assertSame(['src/Metadata/RefreshConnectionMetadata.php'], $found);
    }

    /**
     * Queue a refresh of the connection, as the command does.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     */
    private function queueRefresh(Connection $connection): void
    {
        app(Dispatcher::class)->dispatch(new RefreshConnectionMetadata($connection->id, app(MetadataSettings::class)));
    }

    /**
     * The connection's metadata version as stored.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return int
     */
    private function versionOf(Connection $connection): int
    {
        return Connection::query()->useWritePdo()->findOrFail($connection->id)->metadata_version;
    }

    /**
     * The URLs fetched, in order.
     *
     * @return list<string>
     */
    private function fetchedUrls(): array
    {
        return array_map(static fn (FetchRequest $request): string => $request->url, $this->flowFetcher->requests());
    }

    /**
     * The package's scoped services as currently resolved, by contract.
     *
     * @return array<class-string, object>
     */
    private static function scopedServices(): array
    {
        $services = [];

        foreach ([SingleUseStore::class, AttemptLimiter::class, Enforcement::class, EndpointResolver::class, HandoffIssuer::class] as $service) {
            $services[$service] = app($service);
        }

        return $services;
    }

    /**
     * Assert no connection value is held by the root application or a static
     * property.
     *
     * @return void
     */
    private function assertNothingOfEitherStays(): void
    {
        $values = [
            self::TENANT_A,
            self::TENANT_B,
            self::METADATA_URL,
            self::ISSUER_B,
            $this->connectionA->id,
            $this->connectionB->id,
        ];

        self::assertSame([], $this->retainedBy($values));
        self::assertSame([], $this->retainedByStatics($values));
    }
}
