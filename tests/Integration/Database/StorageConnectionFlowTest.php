<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Completion\Stages\ConsumeRequest;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\AfterCommitDispatcher;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use Tests\Concerns\FlowRoutes;
use Tests\Concerns\RecordsEventSequences;
use Tests\Fixtures\Clients;
use Tests\TestCase;

/**
 * Integration tests of a sign-in whose tables live on a storage connection of
 * their own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageConnection::class)]
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(ConsumeRequest::class)]
#[CoversClass(AfterCommitDispatcher::class)]
final class StorageConnectionFlowTest extends TestCase
{
    use FlowRoutes, RecordsEventSequences;

    /** @var string The connection the package's tables are moved to. */
    private const string STORE = 'sso_flow_store';

    /** @var string The tenant of the connection. */
    private const string TENANT = 'tenant-1';

    /**
     * Bind the application's contracts, create the tables on the storage
     * connection and the routes, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->prepareFlows();
        $this->usePackageTables();
        $this->registerFlowRoutes();
        $this->startRecordingEvents();
    }

    /**
     * A sign-in queries and opens its transactions only on the storage
     * connection, and reports as it commits, while a transaction stays open on
     * the default connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInRunsOnTheStorageConnectionAlone(): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-store');
        $levels     = [];
        $used       = [];

        Event::listen(SsoEvent::class, static function () use (&$levels): void {
            $levels[] = [DB::connection(self::STORE)->transactionLevel(), DB::connection()->transactionLevel()];
        });

        DB::connection()->beginTransaction();

        Event::listen([QueryExecuted::class, TransactionBeginning::class], static function (QueryExecuted|TransactionBeginning $event) use (&$used): void {
            $used[] = $event->connectionName;
        });

        try {
            $redeemed = $this->signedIn($connection);

            $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, ResultUnlinked::class, HandoffIssued::class, HandoffRedeemed::class]);
        } finally {
            DB::connection()->rollBack();
        }

        self::assertSame(['redeemed', $connection->id], [$redeemed['status'], $redeemed['connection']]);
        self::assertSame(array_fill(0, 5, [0, 1]), $levels);
        self::assertSame([self::STORE], array_values(array_unique($used)));
        self::assertNotNull(AuthorizationRequest::query()->sole()->completed_at);
        self::assertSame([
            'single_use.table'             => true,
            'rate_limits.table'            => true,
            'connections.table'            => true,
            'keys.table'                   => false,
            'domains.table'                => false,
            'enforcement.table'            => false,
            'links.table'                  => false,
            'identity_guards.table'        => false,
            'authorization_requests.table' => true,
            'handoff_codes.table'          => true,
        ], array_map(static fn (array $rows): bool => $rows !== [], self::storedRows()));
    }

    /**
     * A start or completion inside a transaction on the storage connection is
     * refused before it writes, and the completion runs once that transaction
     * ends.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStartOrCompletionInsideAStorageTransactionIsRefused(): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-refused');
        $start      = $this->startedFlow($connection);
        $grant      = $this->flowGrant($connection, $start);
        $database   = DB::connection(self::STORE);
        $stored     = self::storedRows();

        $this->startRecordingEvents();

        $database->beginTransaction();

        try {
            self::assertSame(
                'A start runs outside any transaction on the package\'s storage connection: it calls the protocol driver.',
                self::refusal(static fn (): mixed => app(AuthorizationRequestService::class)->start(self::FLOW_APPLICATION, Purpose::SIGN_IN, $connection->id, Clients::browser())),
            );
            self::assertSame(
                'A completion runs outside any transaction on the package\'s storage connection: a rollback would undo its consumption.',
                self::refusal(static fn (): mixed => app(CompletionService::class)->complete(
                    CompletionEndpoint::CALLBACK,
                    $connection->id,
                    new CompletionRequest('GET', $grant->query(), []),
                    Clients::browser(),
                )),
            );
            self::assertSame($stored, self::storedRows());
        } finally {
            $database->rollBack();
        }

        self::assertSame($stored, self::storedRows());
        $this->assertNoEvents();

        $code = $this->completedCode($this->deliverGrant($connection, $grant));

        self::assertSame('redeemed', $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->assertOk()->json('status'));
    }

    /**
     * Add the second connection, and move the storage connection to it.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('database.connections.' . self::STORE, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        config()->set('sso.storage.connection', self::STORE);
    }

    /**
     * The message of the `LogicException` the call throws.
     *
     * @param  \Closure(): mixed  $call
     * @return string
     */
    private static function refusal(\Closure $call): string
    {
        try {
            $call();
        } catch (\LogicException $exception) {
            return $exception->getMessage();
        }

        self::fail('Expected the call to be refused.');
    }

    /**
     * Each package table's name, by its setting key.
     *
     * @return array<string, string>
     */
    private static function tables(): array
    {
        $keys = array_keys(StorageConnection::TABLES);

        return array_combine($keys, array_map(StorageConnection::table(...), $keys));
    }

    /**
     * The rows of each package table on the storage connection, by its setting
     * key.
     *
     * @return array<string, list<array<mixed>>>
     */
    private static function storedRows(): array
    {
        $rows = [];

        foreach (self::tables() as $key => $table) {
            $rows[$key] = array_values(array_map(static fn (object $row): array => (array) $row, DB::connection(self::STORE)->table($table)->get()->all()));
        }

        return $rows;
    }
}
