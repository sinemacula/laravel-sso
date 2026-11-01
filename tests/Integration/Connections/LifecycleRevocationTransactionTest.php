<?php

declare(strict_types = 1);

namespace Tests\Integration\Connections;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\SubjectMigration;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Events\ConnectionDisabled;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Integration tests, on a real database, that a disable, a deletion and a
 * subject migration commit or roll back together with the session revocation
 * each needs (SSO-4.5, SSO-10.5, decision D5): a revocation that writes through
 * the storage connection and succeeds commits with the change; one that writes
 * and then throws leaves neither its write nor anything of the change (the
 * connection, its domains, links, requests and codes, and what was voided), and
 * nothing is reported; and inside a transaction the application opened, a
 * rollback undoes all of it though the helpers succeeded.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionLifecycle::class)]
#[CoversClass(SubjectMigration::class)]
final class LifecycleRevocationTransactionTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The table the revocation writes to, as an adapter writes its revoked sessions. */
    private const string REVOKED = 'example_revoked_sessions';

    /** @var string The tenant the connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var string The failure the revocation throws. */
    private const string FAILURE = 'The sessions could not be revoked.';

    /** @var array<string, string> The settings of a complete OIDC connection. */
    private const array OIDC = [
        'issuer'                 => 'https://idp.example.com',
        'authorization_endpoint' => 'https://idp.example.com/authorize',
        'token_endpoint'         => 'https://idp.example.com/token',
        'jwks_uri'               => 'https://idp.example.com/jwks',
        'client_id'              => 'client-123',
    ];

    /** @var \SineMacula\Laravel\Sso\Models\Connection The tenant's enabled connection. */
    private Connection $connection;

    /** @var array<string, string> The ids of the connection's rows, by what each is. */
    private array $rows;

    /**
     * Bind a fixed clock and a fresh caller, create the tables, the
     * revocation's table and an enabled connection with a verified domain, a
     * link, a request and a code, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        config()->set('sso.features.oidc', true);

        $this->createConnectionTables();
        $this->createDomainsTable();
        $this->createFlowTables();

        Schema::connection(StorageConnection::name())->create(self::REVOKED, static function (Blueprint $table): void {
            $table->id();
            $table->string('kind', 32);
            $table->string('connection_id', 26);
        });

        $created = $this->connections()->create(self::TENANT, 'oidc', 'Acme', self::OIDC);

        $this->connection = Connection::query()->whereKey((string) $created->connection?->id)->sole();
        $this->connection->forceFill(['enabled' => true])->save();

        $this->rows = [
            'domain'  => $this->makeDomain($this->connection, 'example.com', ['state' => DomainState::VERIFIED])->id,
            'link'    => $this->makeLink($this->connection)->id,
            'request' => $this->makeAuthorizationRequest($this->connection)->id,
            'code'    => $this->makeHandoffCode($this->connection)->id,
        ];

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
        Schema::connection(StorageConnection::name())->dropIfExists(self::REVOKED);

        $this->dropFlowTables();
        $this->dropDomainsTable();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A revocation that writes and succeeds commits with the disable, which is
     * then reported once.
     *
     * @return void
     */
    public function testARevocationThatSucceedsCommitsWithTheDisable(): void
    {
        $this->bindRevocation(false);

        self::assertTrue($this->disable()->isChanged());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertFalse($this->reread()->enabled);
        self::assertNotNull(AuthorizationRequest::query()->findOrFail($this->rows['request'])->voided_at);
        self::assertSame([['connection', $this->connection->id]], $this->revoked());
        $this->assertEventSequence([ConnectionDisabled::class]);
    }

    /**
     * Rows of `[change]`: each change that revokes sessions.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideChanges(): iterable
    {
        foreach (['disable', 'delete', 'migrate'] as $change) {
            yield $change => [$change];
        }
    }

    /**
     * A revocation that writes and then throws leaves neither its write nor
     * anything of the change: the connection, its domain, link, request and
     * code are as they were, nothing is voided, and nothing is reported; the
     * exception propagates and no transaction is left open.
     *
     * @param  string  $change
     * @return void
     */
    #[DataProvider('provideChanges')]
    public function testARevocationThatFailsRollsTheChangeBack(string $change): void
    {
        $this->bindRevocation(true);

        try {
            $this->changes()[$change]();
            self::fail('The change succeeded.');
        } catch (\RuntimeException $exception) {
            self::assertSame(self::FAILURE, $exception->getMessage());
        }

        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        $this->assertUntouched();
        $this->assertNoEvents();
    }

    /**
     * Inside a transaction the application opened, each change succeeds and its
     * revocation writes, reporting nothing; the application's rollback then
     * undoes all of it, and still nothing is reported.
     *
     * @param  string  $change
     * @return void
     */
    #[DataProvider('provideChanges')]
    public function testAnApplicationRollbackUndoesTheChange(string $change): void
    {
        $this->bindRevocation(false);

        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        self::assertTrue($this->changes()[$change]()->isChanged());
        self::assertCount(1, $this->revoked());
        $this->assertNoEvents();

        $database->rollBack();

        self::assertSame(0, $database->transactionLevel());
        $this->assertUntouched();
        $this->assertNoEvents();
    }

    /**
     * Assert the connection and its rows are as they were before the change,
     * and the revocation's table holds nothing.
     *
     * @return void
     */
    private function assertUntouched(): void
    {
        $connection = $this->reread();

        self::assertTrue($connection->enabled);
        self::assertSame('client-123', $connection->settings['client_id']);
        self::assertSame(1, Domain::query()->whereKey($this->rows['domain'])->count());
        self::assertSame(1, Link::query()->whereKey($this->rows['link'])->count());
        self::assertNull(AuthorizationRequest::query()->findOrFail($this->rows['request'])->voided_at);
        self::assertNull(HandoffCode::query()->findOrFail($this->rows['code'])->voided_at);
        self::assertSame([], $this->revoked());
    }

    /**
     * Each change that revokes sessions, by name: a disable, a deletion, and a
     * migration that removes the connection's one link.
     *
     * @return array<string, \Closure(): \SineMacula\Laravel\Sso\Connections\ConnectionResult>
     */
    private function changes(): array
    {
        return [
            'disable' => fn (): ConnectionResult => $this->disable(),
            'delete'  => fn (): ConnectionResult => $this->lifecycle()->delete(self::TENANT, $this->connection->id),
            'migrate' => fn (): ConnectionResult => $this->migration()->migrate(self::TENANT, $this->connection->id, ['settings' => ['client_id' => 'client-456']], []),
        ];
    }

    /**
     * Disable the connection.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     */
    private function disable(): ConnectionResult
    {
        return $this->lifecycle()->disable(self::TENANT, $this->connection->id);
    }

    /**
     * Bind a revocation that records the scope in the revocation's table,
     * through the storage connection, and then throws when asked to.
     *
     * @param  bool  $fails
     * @return void
     */
    private function bindRevocation(bool $fails): void
    {
        $this->app?->instance(SessionRevocation::class, new readonly class ($fails, self::REVOKED) implements SessionRevocation {
            /**
             * Constructor.
             *
             * @param  bool  $fails
             * @param  string  $table
             */
            public function __construct(

                /** Whether it throws once it has written. */
                private bool $fails,

                /** The table it writes to. */
                private string $table,
            ) {}

            /**
             * Write the scope's kind and connection, then fail when told to.
             *
             * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function revoke(RevocationScope $scope): void
            {
                DB::connection(StorageConnection::name())->table($this->table)->insert(['kind' => $scope->kind->value, 'connection_id' => (string) $scope->connectionId]);

                if ($this->fails) {
                    throw new \RuntimeException('The sessions could not be revoked.');
                }
            }
        });
    }

    /**
     * Each scope kind and connection the revocation wrote, in order.
     *
     * @return list<array{0: string, 1: string}>
     */
    private function revoked(): array
    {
        $rows = DB::connection(StorageConnection::name())->table(self::REVOKED)->orderBy('id')->get(['kind', 'connection_id'])->all();

        return array_values(array_map(static fn (\stdClass $row): array => [(string) $row->kind, (string) $row->connection_id], $rows));
    }

    /**
     * The connection, read again.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function reread(): Connection
    {
        return Connection::query()->whereKey($this->connection->id)->sole();
    }

    /**
     * The disable and delete helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionLifecycle
     */
    private function lifecycle(): ConnectionLifecycle
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ConnectionLifecycle::class);
    }

    /**
     * The subject migration helper, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Connections\SubjectMigration
     */
    private function migration(): SubjectMigration
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(SubjectMigration::class);
    }

    /**
     * The management helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionService
     */
    private function connections(): ConnectionService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ConnectionService::class);
    }
}
