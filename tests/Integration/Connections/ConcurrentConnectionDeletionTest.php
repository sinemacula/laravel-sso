<?php

declare(strict_types = 1);

namespace Tests\Integration\Connections;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RacesProcesses;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Races a deletion against a link created after the deleter's snapshot, across
 * processes. Skipped on SQLite and without `pcntl`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionLifecycle::class)]
#[CoversClass(LinkStore::class)]
final class ConcurrentConnectionDeletionTest extends TestCase
{
    use RacesProcesses, UsesConnections;

    /** @var string The tenant the connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var string The identity provider's entity id. */
    private const string ENTITY_ID = 'https://idp.example.com/entity';

    /** @var string The deleter holds its snapshot. */
    private const string READ = 'deleter-read';

    /** @var string The link's creation committed. */
    private const string LINKED = 'link-committed';

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection deleted and linked through. */
    private Connection $connection;

    /**
     * Skip where processes cannot share the database, bind the collaborators,
     * and seed a SAML connection.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpRace();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        config()->set('sso.features.saml2', true);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => 'saml2', 'settings' => ['idp_entity_id' => self::ENTITY_ID]]);
    }

    /**
     * Remove the signals and reports.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->tearDownRace();

        parent::tearDown();
    }

    /**
     * A link created after the deleter's snapshot is never left behind:
     * PostgreSQL fails to serialise, MySQL deletes it.
     *
     * @return void
     */
    public function testALinkCreatedAfterTheDeletersSnapshotIsNeverLeftBehind(): void
    {
        $reports  = $this->race([$this->deleter(), $this->linker()]);
        $reported = (string) json_encode($reports);
        $pgsql    = DB::connection()->getDriverName() === 'pgsql';

        self::assertSame(['result' => 'created', 'error' => null], $reports[1], $reported);
        self::assertSame($pgsql ? ['result' => null, 'error' => self::RACE_SERIALIZATION_FAILURE] : ['result' => 'deleted', 'error' => null], $reports[0], $reported);
        self::assertSame($pgsql ? [1, 1] : [0, 0], [Connection::query()->whereKey($this->connection->id)->count(), $this->links()], $reported);
    }

    /**
     * The deleter: read under `REPEATABLE READ`, signal, wait for the link,
     * then delete and commit.
     *
     * @return \Closure(): string
     */
    private function deleter(): \Closure
    {
        $connectionId = $this->connection->id;

        return function () use ($connectionId): string {

            $database = DB::connection(StorageConnection::name());

            $database->statement(self::repeatableReadStatement($database->getDriverName()));
            $database->beginTransaction();

            Connection::query()->whereKey($connectionId)->get();
            $this->links();

            $this->signal(self::READ);
            $this->awaitSignal(self::LINKED);

            $status = app(ConnectionLifecycle::class)->delete(self::TENANT, $connectionId, Clients::browser())->status->value;

            $database->commit();

            return $status;
        };
    }

    /**
     * The linker: wait for the deleter's snapshot, link a subject through the
     * connection, and signal once committed.
     *
     * @return \Closure(): string
     */
    private function linker(): \Closure
    {
        $connectionId = $this->connection->id;

        return function () use ($connectionId): string {

            $this->awaitSignal(self::READ);

            try {
                return app(LinkStore::class)->create(
                    Connection::query()->findOrFail($connectionId),
                    new LinkSubject(self::ENTITY_ID, 'subject-1'),
                    new IdentityReference('user', '1'),
                    LinkOrigin::LINK_PURPOSE,
                    Clients::browser(),
                )->status->value;
            } finally {
                $this->signal(self::LINKED);
            }
        };
    }

    /**
     * How many links the connection has.
     *
     * @return int
     */
    private function links(): int
    {
        return Link::query()->where('connection_id', $this->connection->id)->count();
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
}
