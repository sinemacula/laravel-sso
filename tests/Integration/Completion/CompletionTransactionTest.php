<?php

declare(strict_types = 1);

namespace Tests\Integration\Completion;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * How a completion meets transactions, on every database the suite runs on
 * (SSO-10.5, SSO-11.4, decision D5): an issuer that throws, and a database
 * error in the locked steps, roll the locked steps back, so nothing is
 * reported and `completed_at` stays unset, while the request stays consumed;
 * a database error before the steps propagates and reports nothing; and a
 * completion called inside the caller's transaction on the storage connection
 * is a `LogicException` before it writes anything, so no rollback of the
 * caller's can undo a consumption (SSO-5.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(CompletionPipeline::class)]
final class CompletionTransactionTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var string The protocol state the request was started with. */
    private const string STATE = 'the-protocol-state-of-the-committed-request';

    /** @var \Tests\Fixtures\Handoffs\RecordingHandoffIssuer The handoff issuer. */
    private RecordingHandoffIssuer $issuer;

    /** @var \Tests\Fixtures\Protocols\VerifyingDriver The driver the connection runs over. */
    private VerifyingDriver $driver;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Models\AuthorizationRequest The request the response answers. */
    private AuthorizationRequest $request;

    /**
     * Bind a fixed clock and the recording issuer, register the application and
     * the driver, create the tables, a usable connection and a request, and
     * record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->issuer = new RecordingHandoffIssuer;
        $this->driver = new VerifyingDriver;
        $driver       = $this->driver;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(HandoffIssuer::class, $this->issuer);

        config()->set('sso.features.oidc', true);
        config()->set('sso.applications', [
            'web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true, 'unlinked_handoffs' => true],
        ]);

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->createDomainsTable();
        self::migration(self::SINGLE_USE_MIGRATION)->up(); // @phpstan-ignore method.notFound
        self::migration(self::RATE_LIMITS_MIGRATION)->up(); // @phpstan-ignore method.notFound

        $this->connection = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);
        $this->request    = $this->makeAuthorizationRequest($this->connection, [
            'state_digest'      => hash('sha256', self::STATE),
            'handoff_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_verifier'     => app(SecretEncrypter::class)->encrypt('the-pkce-verifier-of-the-committed-request-'),
        ]);

        $this->startRecordingEvents();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::migration(self::RATE_LIMITS_MIGRATION)->down(); // @phpstan-ignore method.notFound
        self::migration(self::SINGLE_USE_MIGRATION)->down(); // @phpstan-ignore method.notFound
        $this->dropDomainsTable();
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * An issuer that throws propagates its exception, never a failure: the
     * locked steps roll back, so nothing is reported and `completed_at` stays
     * unset, while the request stays consumed and a replay is rejected.
     *
     * @return void
     */
    public function testAThrowingIssuerRollsTheCompletionBack(): void
    {
        $failure = new \RuntimeException('The handoff store cannot be written.');

        $this->issuer->failure = $failure;

        try {
            $this->completeAtCallback();
            self::fail('A completion whose issuer threw completed.');
        } catch (\RuntimeException $e) {
            self::assertSame($failure, $e);
        }

        $row = $this->reread();

        self::assertNotNull($row->consumed_at);
        self::assertNull($row->completed_at);
        $this->assertNoEvents();

        $this->issuer->failure = null;

        self::assertSame(FailureReason::REQUEST_UNKNOWN, $this->completeAtCallback()->reason);
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::REQUEST_UNKNOWN);
    }

    /**
     * A database error in the locked steps (the link store reading a table that
     * is gone) propagates, and rolls the locked steps back.
     *
     * @return void
     */
    public function testADatabaseErrorInTheLockedStepsPropagatesAndRollsBack(): void
    {
        $this->app?->instance(Linker::class, app(LinkStore::class));

        Schema::connection(StorageConnection::name())->dropIfExists(StorageConnection::table('links.table'));

        try {
            $this->completeAtCallback();
            self::fail('A completion whose link store failed completed.');
        } catch (QueryException) {
            // A server error, as it should be
        }

        self::assertNotNull($this->reread()->consumed_at);
        self::assertNull($this->reread()->completed_at);
        self::assertSame([], $this->issuer->grants());
        $this->assertNoEvents();
    }

    /**
     * A database error before the steps (the requests table gone) propagates
     * and reports nothing.
     *
     * @return void
     */
    public function testADatabaseErrorBeforeTheLockedStepsPropagates(): void
    {
        Schema::connection(StorageConnection::name())->dropIfExists(StorageConnection::table('authorization_requests.table'));

        try {
            $this->completeAtCallback();
            self::fail('A completion whose requests table is gone completed.');
        } catch (QueryException) {
            // A server error, as it should be
        }

        $this->assertNoEvents();
    }

    /**
     * Each endpoint a completion arrives at.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function endpoints(): iterable
    {
        yield 'assertion consumer service' => ['assertionConsumerService'];
        yield 'callback' => ['callback'];
    }

    /**
     * A completion called inside the caller's transaction on the storage
     * connection is refused before it writes anything: no attempt counted, no
     * request correlated, consumed or recorded, and nothing reported. Once the
     * caller's transaction is over, the request completes.
     *
     * @param  string  $endpoint
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('endpoints')]
    public function testACompletionInsideACallersTransactionIsRefusedBeforeItWrites(string $endpoint): void
    {
        $database = DB::connection(StorageConnection::name());
        $service  = app(CompletionService::class);
        $request  = new CompletionRequest('GET', 'state=' . self::STATE, []);

        $database->beginTransaction();

        try {
            $endpoint === 'callback' ? $service->callback($this->connection->id, $request) : $service->assertionConsumerService($this->connection->id, $request);

            self::fail('A completion inside the caller\'s transaction was answered.');
        } catch (\LogicException $exception) {
            self::assertSame(
                'A completion runs outside any transaction on the package\'s storage connection: a rollback would undo its consumption.',
                $exception->getMessage(),
            );
        } finally {
            $database->rollBack();
        }

        self::assertNull($this->reread()->consumed_at);
        self::assertSame(0, DB::table(StorageConnection::table('single_use.table'))->count());
        self::assertSame(0, DB::table(StorageConnection::table('rate_limits.table'))->count());
        self::assertSame(0, $this->driver->correlations());
        $this->assertNoEvents();

        self::assertTrue($this->completeAtCallback()->isCompleted());
        $this->assertEventSequence([ResultVerified::class, HandoffIssued::class]);
    }

    /**
     * Complete at the callback with the state.
     *
     * @param  string  $state
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \Illuminate\Database\QueryException
     */
    private function completeAtCallback(string $state = self::STATE): CompletionResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(CompletionService::class)->callback($this->connection->id, new CompletionRequest('GET', 'state=' . $state, []));
    }

    /**
     * The request, read again.
     *
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function reread(): AuthorizationRequest
    {
        return AuthorizationRequest::query()->whereKey($this->request->id)->sole();
    }

    /**
     * The shipped migration of the file.
     *
     * @param  string  $file
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function migration(string $file): Migration
    {
        return require dirname(__DIR__, 3) . $file;
    }
}
