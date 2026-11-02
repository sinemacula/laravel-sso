<?php

declare(strict_types = 1);

namespace Tests\Integration\Metadata;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Completion\Stages\ValidateResponse;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Metadata\MetadataApplier;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\RefreshResult;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Races a metadata refresh across processes, each with its own database
 * connection, on PostgreSQL and MySQL (SSO-2.8, SSO-2.13, SSO-11.12):
 *
 * - two refreshers of one connection: the claim lets exactly one fetch, and the
 *   other is `in_progress` (an administrator's) or finds nothing due (the
 *   schedule's);
 * - a refresh paused between its fetch and its write while an administrator
 *   distrusts a certificate, adds an identity provider signing certificate
 *   (additive, which raises no trust version) or adds a metadata signing
 *   anchor: the refresh is refused `metadata_conflict` and the administrator's
 *   change stands, so a refresh never removes a certificate added while it
 *   fetched;
 * - a refresh whose claim expired while it fetched and was taken over by
 *   another server's refresh: the one that lost its claim writes nothing,
 *   whether it then applies or records a failure, and the new owner's
 *   refresh stands;
 * - a refresh removing a certificate while a completion through the connection
 *   is between its validation and its lock: the completion is refused
 *   `connection_unavailable` under its lock.
 *
 * The order is forced with signal files, never with timing. A refresh and a
 * completion refuse to run inside a transaction, so they always run plainly;
 * the administrator runs plainly, and again inside a `REPEATABLE READ`
 * transaction of its own that read the connection and its keys before the
 * refresh claimed it. On PostgreSQL that transaction then fails to serialise
 * (SQLSTATE 40001) when it locks the connection the claim wrote, which leaves
 * the refresh to apply: an accepted safe outcome, on PostgreSQL only.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataRefresher::class)]
#[CoversClass(MetadataApplier::class)]
#[CoversClass(KeyService::class)]
final class ConcurrentMetadataRefreshTest extends TestCase
{
    use UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The tenant the connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var string The URL the provider serves its metadata at. */
    private const string URL = 'https://idp.example.test/metadata.xml';

    /** @var float How long, in seconds, a process waits for another before it gives up. */
    private const float DEADLINE_SECONDS = 30.0;

    /** @var string What a process reports for a serialisation failure. */
    private const string SERIALIZATION_FAILURE = 'serialization_failure';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var ?\SineMacula\Laravel\Sso\Models\Connection The connection raced over. */
    private ?Connection $connection = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher every process fetches through. */
    private FakeFetcher $fetcher;

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database; bind a fixed clock, a
     * fresh caller, a fake fetcher, a limiter that allows every attempt and a
     * linker that links every result to one identity; switch SAML and the
     * refresh on; register the application and the endpoints; create the
     * tables, a refreshing connection trusting the provider's certificate and
     * another, and the directory the processes use.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        $this->fetcher = new FakeFetcher;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(Fetcher::class, $this->fetcher);
        $this->app?->instance('request', Request::create('/auth/sso/authorization-requests', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));
        $this->app?->instance(AttemptLimiter::class, new readonly class implements AttemptLimiter {
            /**
             * Allow every attempt.
             *
             * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject  $subject
             * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptResult
             */
            #[\Override]
            public function attempt(AttemptSubject $subject): AttemptResult
            {
                unset($subject);

                return AttemptResult::allowed();
            }
        });
        $this->app?->instance(Linker::class, new readonly class implements Linker {
            /**
             * One identity for every result.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
             */
            #[\Override]
            public function resolve(VerifiedResult $result): IdentityReference
            {
                unset($result);

                return new IdentityReference('App\Models\User', '42');
            }
        });

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.metadata_refresh', true);
        config()->set('sso.endpoints.base_url', 'https://api.example.com');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->createDomainsTable();
        self::singleUseMigration()->up(); // @phpstan-ignore method.notFound

        $this->connection = $this->makeConnection(['protocol' => 'saml2', 'enabled' => true, 'settings' => [
            'idp_entity_id'    => FakeSamlIdentityProvider::ENTITY_ID,
            'sso_url'          => FakeSamlIdentityProvider::SSO_URL,
            'sso_binding'      => 'http_redirect',
            'metadata_url'     => self::URL,
            'metadata_refresh' => true,
        ]]);

        $this->trust(self::idp()->certificate());
        $this->trust(Certificates::distinct(9));

        $this->outcomes = sys_get_temp_dir() . '/metadata-refresh-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the signals and outcomes and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if (isset($this->outcomes) && is_dir($this->outcomes)) {

            foreach (glob($this->outcomes . '/*') ?: [] as $file) {
                @unlink($file);
            }

            @rmdir($this->outcomes);
        }

        if ($this->connection !== null) {
            self::singleUseMigration()->down(); // @phpstan-ignore method.notFound
            $this->dropDomainsTable();
            $this->dropFlowTables();
            $this->dropConnectionTables();
        }

        parent::tearDown();
    }

    /**
     * Rows of `[second, outcome]`: how the second refresher runs, and what it
     * reports.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideSecondRefreshers(): iterable
    {
        yield from [
            'an administrators refresh' => ['now', 'in_progress'],
            'the schedule'              => ['due', 'nothing_due'],
        ];
    }

    /**
     * Two refreshers of one connection: the first claims it and fetches, and
     * the second, running while the first fetches, fetches nothing.
     *
     * @param  string  $second
     * @param  string  $outcome
     * @return void
     */
    #[DataProvider('provideSecondRefreshers')]
    public function testExactlyOneOfTwoRefreshersFetches(string $second, string $outcome): void
    {
        $fetching = "{$this->outcomes}/fetching";
        $done     = "{$this->outcomes}/second-done";
        $outcomes = $this->outcomes;

        $this->serveWhen(self::metadata(), static function () use ($fetching, $done, $outcomes): void {
            touch("{$outcomes}/fetched-" . getmypid());
            touch($fetching);
            self::await($done);
        });

        [$first, $other] = $this->inProcesses([
            fn (): array => ['status' => $this->refresher()->refreshNow(self::TENANT, $this->connectionId(), self::actor())->outcome->value],
            function () use ($second, $fetching, $done): array {

                self::await($fetching);

                try {
                    return ['status' => $this->secondRefresh($second)];
                } finally {
                    touch($done);
                }
            },
        ]);

        $reported = (string) json_encode([$first, $other]);

        self::assertSame('refreshed', $first['status'] ?? null, $reported);
        self::assertSame($outcome, $other['status'] ?? null, $reported);
        self::assertCount(1, glob("{$this->outcomes}/fetched-*") ?: [], $reported);
        self::assertSame(1, $this->row()->metadata_version);
    }

    /**
     * Rows of `[change, in transaction]`: what the administrator changes while
     * the refresh is paused, plainly or inside a transaction of its own.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideAdministratorChanges(): iterable
    {
        yield from [
            'a certificate distrusted'                      => ['distrust', false],
            'a certificate distrusted inside a transaction' => ['distrust', true],
            'a certificate added'                           => ['add', false],
            'a certificate added inside a transaction'      => ['add', true],
            'an anchor added'                               => ['anchor', false],
            'an anchor added inside a transaction'          => ['anchor', true],
        ];
    }

    /**
     * A refresh paused between its fetch and its write while an administrator
     * changes the connection's trust is refused `metadata_conflict` and writes
     * nothing, and the administrator's change stands; on PostgreSQL, an
     * administrator inside a transaction older than the refresh's claim fails
     * to serialise instead, changes nothing, and the refresh applies.
     *
     * @param  string  $change
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideAdministratorChanges')]
    public function testARefreshPausedBetweenFetchAndWriteLosesToAnAdministratorsChange(string $change, bool $inTransaction): void
    {
        $read    = "{$this->outcomes}/administrator-read";
        $fetched = "{$this->outcomes}/fetched";
        $changed = "{$this->outcomes}/changed";

        $published = [self::idp()->certificate(), Certificates::distinct(9), Certificates::distinct(10)];

        $this->serveWhen(self::metadata()->with(['signing_certificates' => $published]), static function () use ($fetched, $changed): void {
            touch($fetched);
            self::await($changed);
        });

        [$administrator, $refresh] = $this->inProcesses([
            fn (): array => $this->administrator($change, $inTransaction, $read, $fetched, $changed),
            function () use ($read): array {

                self::await($read);

                $result = $this->refresher()->refreshNow(self::TENANT, $this->connectionId(), self::actor());

                return ['status' => $result->outcome->value, 'reason' => $result->reason?->value];
            },
        ]);

        $reported = (string) json_encode([$administrator, $refresh]);
        $failed   = $inTransaction && DB::connection()->getDriverName() === 'pgsql';

        self::assertSame($failed ? self::SERIALIZATION_FAILURE : ($change === 'distrust' ? 'distrusted' : 'trusted'), $administrator['status'] ?? null, $reported);
        self::assertSame($failed || $change !== 'distrust' ? 0 : 1, $this->row()->trust_version, $reported);
        self::assertSame($failed ? ['refreshed', null] : ['conflict', 'metadata_conflict'], [$refresh['status'] ?? null, $refresh['reason'] ?? null], $reported);
        self::assertSame(self::expectedKeys($change, $failed), $this->keys(), $reported);
        self::assertSame($failed ? 1 : 0, $this->row()->metadata_version, $reported);
    }

    /**
     * Rows of `[served]`: what the refresh whose claim is taken over is served,
     * the metadata to apply or a failed fetch to record.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideLostClaims(): iterable
    {
        yield from [
            'the loser applying'          => [true],
            'the loser recording failure' => [false],
        ];
    }

    /**
     * A refresh whose claim expired while it fetched, and was taken over by
     * another server's refresh once it had, writes nothing when it then applies
     * or records a failure: it is `conflict`, and the other refresh's write,
     * which published a further certificate, stands.
     *
     * @param  bool  $served
     * @return void
     */
    #[DataProvider('provideLostClaims')]
    public function testARefreshWhoseClaimWasTakenOverWritesNothing(bool $served): void
    {
        $fetching = "{$this->outcomes}/first-fetching";
        $taken    = "{$this->outcomes}/claim-taken";
        $winner   = self::metadata()->with(['signing_certificates' => [self::idp()->certificate(), Certificates::distinct(9), Certificates::distinct(10)]])->toXml();

        $this->fetcher->respond(self::URL, static function () use ($fetching, $taken, $served): FetchResult {
            touch($fetching);
            self::await($taken);

            return $served ? FetchResult::fetched(200, [], self::metadata()->toXml()) : FetchResult::failed();
        });

        [$loser, $owner] = $this->inProcesses([
            function (): array {
                $result = $this->refresher()->refreshNow(self::TENANT, $this->connectionId(), self::actor());

                return ['status' => $result->outcome->value, 'reason' => $result->reason?->value];
            },
            function () use ($fetching, $taken, $winner): array {

                self::await($fetching);

                try {
                    app()->instance(Clock::class, new FixedClock('2026-11-01T09:35:01Z'));
                    $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], $winner));

                    $result = $this->refresher()->refreshNow(self::TENANT, $this->connectionId(), self::actor());
                } finally {
                    touch($taken);
                }

                return ['status' => $result->outcome->value, 'reason' => $result->reason?->value];
            },
        ]);

        $reported = (string) json_encode([$loser, $owner]);
        $row      = $this->row();

        self::assertSame(['status' => 'refreshed', 'reason' => null], $owner, $reported);
        self::assertSame(['status' => 'conflict', 'reason' => 'metadata_conflict'], $loser, $reported);
        self::assertSame([1, 0, null, '2026-11-01T09:35:01+00:00'], [
            $row->metadata_version,
            $row->metadata_refresh_failures,
            $row->metadata_claim_token,
            $row->metadata_fetched_at?->toIso8601String(),
        ], $reported);
        self::assertSame(self::expectedKeys('distrust', true), $this->keys(), $reported);
    }

    /**
     * A refresh removing a certificate while a completion through the
     * connection is between its validation and its lock voids the completion's
     * request under the connection's lock, and the completion is refused
     * `connection_unavailable` under its own, with no code issued and no
     * assertion recorded.
     *
     * @return void
     */
    public function testACompletionValidatedBeforeARefreshRemovedACertificateIsRefused(): void
    {
        $validated = "{$this->outcomes}/validated";
        $refreshed = "{$this->outcomes}/refreshed";
        $request   = $this->solicitedResponse();

        $this->serveWhen(self::metadata());

        [$completion, $refresh] = $this->inProcesses([
            function () use ($request, $validated, $refreshed): array {

                $this->pauseAfterValidation($validated, $refreshed);

                $result = app(CompletionService::class)->assertionConsumerService($this->connectionId(), $request);

                return ['status' => $result->status->value, 'reason' => $result->reason?->value];
            },
            function () use ($validated, $refreshed): array {

                self::await($validated);

                try {
                    $result = $this->refresher()->refreshNow(self::TENANT, $this->connectionId(), self::actor());
                } finally {
                    touch($refreshed);
                }

                return ['status' => $result->outcome->value, 'trust_changed' => $result->trustChanged];
            },
        ]);

        $reported = (string) json_encode([$completion, $refresh]);
        $stored   = AuthorizationRequest::query()->where('connection_id', $this->connectionId())->sole();

        self::assertSame(['status' => 'refreshed', 'trust_changed' => true], $refresh, $reported);
        self::assertSame(['status' => 'failed', 'reason' => 'connection_unavailable'], $completion, $reported);
        self::assertNotNull($stored->voided_at, $reported);
        self::assertSame(0, HandoffCode::query()->where('connection_id', $this->connectionId())->count(), $reported);
        self::assertSame(0, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count(), $reported);
        self::assertNotNull($stored->completed_at, $reported);
        self::assertSame([MaskedKey::fromCertificate(self::idp()->certificate())->fingerprint], $this->keys()['idp_signing'] ?? null);
    }

    /**
     * Wait until the other process has signalled, and fail loudly once the
     * deadline passes without it: the process then reports an error, so a race
     * whose processes ran one after the other never passes as one that
     * overlapped.
     *
     * @param  string  $signal
     * @return void
     *
     * @throws \RuntimeException
     */
    public static function await(string $signal): void
    {
        $deadline = microtime(true) + self::DEADLINE_SECONDS;

        while (!file_exists($signal)) {

            if (microtime(true) > $deadline) {
                throw new \RuntimeException(sprintf('The barrier timed out waiting for [%s].', basename($signal)));
            }

            usleep(5000);
            clearstatcache(true, $signal);
        }
    }

    /**
     * The second refresh, as it reports itself: an administrator's outcome, or
     * whether the schedule found anything due.
     *
     * @param  string  $second
     * @return string
     */
    private function secondRefresh(string $second): string
    {
        if ($second === 'now') {
            return $this->refresher()->refreshNow(self::TENANT, $this->connectionId(), self::actor())->outcome->value;
        }

        $results = $this->refresher()->refreshDue();

        return $results === [] ? 'nothing_due' : implode(',', array_map(static fn (RefreshResult $result): string => $result->outcome->value, $results));
    }

    /**
     * In a forked process: inside a `REPEATABLE READ` transaction that read the
     * connection and its keys first, or plainly, signal it has read, wait for
     * the refresh to fetch, then distrust the second certificate, add a signing
     * certificate or add an anchor, and signal once that is done or failed.
     *
     * @param  string  $change
     * @param  bool  $inTransaction
     * @param  string  $read
     * @param  string  $fetched
     * @param  string  $changed
     * @return array<string, mixed>
     *
     * @throws \Throwable
     */
    private function administrator(string $change, bool $inTransaction, string $read, string $fetched, string $changed): array
    {
        $database = DB::connection(StorageConnection::name());
        $id       = $this->connectionId();
        $print    = MaskedKey::fromCertificate(Certificates::distinct(9))->fingerprint;
        $second   = ConnectionKey::query()->where('connection_id', $id)->where('fingerprint', $print)->value('id');

        self::assertIsString($second);

        if ($inTransaction) {
            $database->statement(self::repeatableReadStatement($database->getDriverName()));
            $database->beginTransaction();

            Connection::query()->whereKey($id)->get();
            ConnectionKey::query()->where('connection_id', $id)->get();
        }

        touch($read);
        self::await($fetched);

        try {
            $result = match ($change) {
                'distrust' => app(KeyService::class)->distrustCertificate(self::TENANT, $id, $second),
                'add'      => app(KeyService::class)->trustCertificate(self::TENANT, $id, Certificates::distinct(11)),
                default    => app(KeyService::class)->trustCertificate(self::TENANT, $id, Certificates::distinct(11), use: KeyUse::METADATA_SIGNING),
            };

            if ($inTransaction) {
                $database->commit();
            }

            return ['status' => $result->status->value];
        } catch (\Throwable $exception) {

            if ($database->transactionLevel() > 0) {
                $database->rollBack();
            }

            if (!self::isSerializationFailure($exception)) {
                throw $exception;
            }

            return ['status' => self::SERIALIZATION_FAILURE];
        } finally {
            touch($changed);
        }
    }

    /**
     * Have the completion's validation stage, once it has validated, signal and
     * wait for the refresh, so the completion takes its lock after the refresh
     * committed.
     *
     * @param  string  $validated
     * @param  string  $refreshed
     * @return void
     */
    private function pauseAfterValidation(string $validated, string $refreshed): void
    {
        app()->bind(ValidateResponse::class, static function ($app) use ($validated, $refreshed): CompletionStage {

            $stage = $app->build(ValidateResponse::class);

            return new readonly class ($stage, $validated, $refreshed) implements CompletionStage {
                /**
                 * Constructor.
                 *
                 * @param  \SineMacula\Laravel\Sso\Completion\Stages\ValidateResponse  $stage
                 * @param  string  $validated
                 * @param  string  $refreshed
                 */
                public function __construct(

                    /** The real validation. */
                    private ValidateResponse $stage,

                    /** The signal that the response was validated. */
                    private string $validated,

                    /** The signal that the refresh committed. */
                    private string $refreshed,
                ) {}

                /**
                 * Validate, signal, and wait for the refresh.
                 *
                 * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
                 * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
                 */
                #[\Override]
                public function run(CompletionState $state): StageOutcome
                {
                    $outcome = $this->stage->run($state);

                    touch($this->validated);
                    ConcurrentMetadataRefreshTest::await($this->refreshed);

                    return $outcome;
                }
            };
        });
    }

    /**
     * Start a `sign_in` through the connection and answer what the provider's
     * signed response to it posts to the assertion consumer service.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\CompletionRequest
     */
    private function solicitedResponse(): CompletionRequest
    {
        $connection = Connection::query()->findOrFail($this->connectionId());
        $start      = app(AuthorizationRequestService::class)->start('web', Purpose::SIGN_IN, $connection->id);

        self::assertTrue($start->isStarted());

        parse_str((string) parse_url((string) $start->navigation?->url(), PHP_URL_QUERY), $query);

        $document = new \DOMDocument;

        $encoded    = $query['SAMLRequest'] ?? null;
        $relayState = $query['RelayState']  ?? null;

        self::assertIsString($encoded);
        self::assertIsString($relayState);
        self::assertTrue($document->loadXML((string) gzinflate((string) base64_decode($encoded, true)), LIBXML_NONET));

        $endpoints = app(EndpointResolver::class)->endpoints($connection);
        $response  = self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, app(Clock::class)->now());

        return $response->inResponseTo($document->documentElement?->getAttribute('ID'))->completionRequest($relayState);
    }

    /**
     * Serve the metadata at the URL, running the hook first as it is fetched.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata  $metadata
     * @param  ?\Closure(): void  $hook
     * @return void
     */
    private function serveWhen(FakeSamlMetadata $metadata, ?\Closure $hook = null): void
    {
        $xml = $metadata->toXml();

        $this->fetcher->respond(self::URL, static function (FetchRequest $request) use ($xml, $hook): FetchResult {
            unset($request);

            if ($hook !== null) {
                $hook();
            }

            return FetchResult::fetched(200, [], $xml);
        });
    }

    /**
     * The keys of the connection by use, each use's fingerprints sorted.
     *
     * @return array<string, list<string>>
     */
    private function keys(): array
    {
        $keys = [];

        foreach (ConnectionKey::query()->where('connection_id', $this->connectionId())->get() as $key) {
            $keys[$key->use->value][] = $key->fingerprint;
        }

        ksort($keys);

        return array_map(static function (array $fingerprints): array {
            sort($fingerprints);

            return $fingerprints;
        }, $keys);
    }

    /**
     * The keys the connection holds once the race ends: the administrator's
     * change made and the refresh's refused, or, when the administrator failed
     * to serialise, the refresh's applied.
     *
     * @param  string  $change
     * @param  bool  $failed
     * @return array<string, list<string>>
     */
    private static function expectedKeys(string $change, bool $failed): array
    {
        $fingerprint = static fn (string $certificate): string => (string) MaskedKey::fromCertificate($certificate)->fingerprint;
        $sorted      = static function (array $certificates) use ($fingerprint): array {
            $fingerprints = array_map($fingerprint, $certificates);

            sort($fingerprints);

            return $fingerprints;
        };

        $signing = match (true) {
            $failed                => $sorted([self::idp()->certificate(), Certificates::distinct(9), Certificates::distinct(10)]),
            $change === 'distrust' => $sorted([self::idp()->certificate()]),
            $change === 'add'      => $sorted([self::idp()->certificate(), Certificates::distinct(9), Certificates::distinct(11)]),
            default                => $sorted([self::idp()->certificate(), Certificates::distinct(9)]),
        };

        return $change === 'anchor' && !$failed ? ['idp_signing' => $signing, 'metadata_signing' => $sorted([Certificates::distinct(11)])] : ['idp_signing' => $signing];
    }

    /**
     * Trust the certificate for the connection.
     *
     * @param  string  $certificate
     * @return void
     */
    private function trust(string $certificate): void
    {
        $masked = MaskedKey::fromCertificate($certificate);

        (new ConnectionKey)->forceFill([
            'connection_id' => $this->connectionId(),
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

    /**
     * The connection as stored now.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function row(): Connection
    {
        return Connection::query()->findOrFail($this->connectionId());
    }

    /**
     * The id of the connection raced over.
     *
     * @return string
     */
    private function connectionId(): string
    {
        return (string) $this->connection?->id;
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
     * Fork a process per body, have each run its body on a connection of its
     * own, and collect what each reported, in order.
     *
     * @param  list<\Closure(): array<string, mixed>>  $bodies
     * @return list<array<string, mixed>>
     */
    private function inProcesses(array $bodies): array
    {
        DB::disconnect();

        $pids = [];

        foreach ($bodies as $process => $body) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $body);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        $outcomes = [];

        foreach (array_keys($bodies) as $process) {

            $outcome = json_decode((string) file_get_contents("{$this->outcomes}/{$process}"), true);

            $outcomes[] = is_array($outcome) ? $outcome : ['status' => 'unreadable'];
        }

        return $outcomes;
    }

    /**
     * In a forked process: open a connection of its own, run the body, report
     * what it answered, a PostgreSQL serialisation failure, or the error it
     * threw, and end without running the parent's shutdown.
     *
     * @param  int  $process
     * @param  \Closure(): array<string, mixed>  $body
     * @return never
     */
    private function runInChild(int $process, \Closure $body): never
    {
        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            $outcome = $body();
        } catch (\Throwable $e) {
            $outcome = self::isSerializationFailure($e) ? ['status' => self::SERIALIZATION_FAILURE] : ['status' => 'error', 'reason' => $e::class . ': ' . $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/{$process}", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Whether the error, or one it was thrown for, is PostgreSQL's
     * serialisation failure: SQLSTATE 40001 on PostgreSQL. Inside a caller's
     * transaction, Laravel rethrows it as a `DeadlockException` whose previous
     * error is the query's.
     *
     * @param  \Throwable  $exception
     * @return bool
     */
    private static function isSerializationFailure(\Throwable $exception): bool
    {
        for ($error = $exception; $error !== null; $error = $error->getPrevious()) {
            if ($error instanceof QueryException && (string) $error->getCode() === '40001') {
                return DB::connection()->getDriverName() === 'pgsql';
            }
        }

        return false;
    }

    /**
     * The statement that makes every later transaction of the session
     * `REPEATABLE READ`.
     *
     * @param  string  $driver
     * @return string
     *
     * @throws \LogicException
     */
    private static function repeatableReadStatement(string $driver): string
    {
        return match ($driver) {
            'pgsql' => 'set session characteristics as transaction isolation level repeatable read',
            'mysql' => 'set session transaction isolation level repeatable read',
            default => throw new \LogicException(sprintf('No statement sets the isolation on [%s].', $driver)),
        };
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

    /**
     * The shipped migration of the single-use keys.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function singleUseMigration(): Migration
    {
        return require dirname(__DIR__, 3) . self::SINGLE_USE_MIGRATION;
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
