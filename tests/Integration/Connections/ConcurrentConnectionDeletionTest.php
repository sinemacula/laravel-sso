<?php

declare(strict_types = 1);

namespace Tests\Integration\Connections;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RacesProcesses;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Races a deletion against a link, key, certificate or domain claim written
 * after the deleter's snapshot, across processes. Skipped on SQLite and without
 * `pcntl`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionLifecycle::class)]
#[CoversClass(LinkStore::class)]
#[CoversClass(KeyService::class)]
#[CoversClass(DomainService::class)]
final class ConcurrentConnectionDeletionTest extends TestCase
{
    use RacesProcesses, UsesConnections;

    /** @var string The tenant the connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var string The identity provider's entity id. */
    private const string ENTITY_ID = 'https://idp.example.com/entity';

    /** @var string The deleter holds its snapshot. */
    private const string READ = 'deleter-read';

    /** @var string The writer committed. */
    private const string WRITTEN = 'write-committed';

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection deleted and written to. */
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
     * Rows of `[writer, status, model]`: the write, the status it answers and
     * the model of the row it inserts.
     *
     * @return iterable<string, array{0: string, 1: string, 2: class-string<\SineMacula\Laravel\Sso\Models\SsoModel>}>
     */
    public static function provideWriters(): iterable
    {
        yield from [
            'a link'                => ['link', 'created', Link::class],
            'a key'                 => ['key', 'added', ConnectionKey::class],
            'a trusted certificate' => ['certificate', 'trusted', ConnectionKey::class],
            'a domain claim'        => ['domain', 'claimed', Domain::class],
        ];
    }

    /**
     * A row written after the deleter's snapshot is never left behind:
     * PostgreSQL fails to serialise, MySQL deletes it.
     *
     * @param  string  $writer
     * @param  string  $status
     * @param  class-string<\SineMacula\Laravel\Sso\Models\SsoModel>  $model
     * @return void
     */
    #[DataProvider('provideWriters')]
    public function testARowWrittenAfterTheDeletersSnapshotIsNeverLeftBehind(string $writer, string $status, string $model): void
    {
        $reports  = $this->race([$this->deleter($model), $this->writer($writer)]);
        $reported = (string) json_encode($reports);
        $pgsql    = DB::connection()->getDriverName() === 'pgsql';

        self::assertSame(['result' => $status, 'error' => null], $reports[1], $reported);
        self::assertSame($pgsql ? ['result' => null, 'error' => self::RACE_SERIALIZATION_FAILURE] : ['result' => 'deleted', 'error' => null], $reports[0], $reported);
        self::assertSame($pgsql ? [1, 1] : [0, 0], [Connection::query()->whereKey($this->connection->id)->count(), $this->rowsOf($model)], $reported);
    }

    /**
     * The deleter: read under `REPEATABLE READ`, signal, wait for the write,
     * then delete and commit.
     *
     * @param  class-string<\SineMacula\Laravel\Sso\Models\SsoModel>  $model
     * @return \Closure(): string
     */
    private function deleter(string $model): \Closure
    {
        $connectionId = $this->connection->id;

        return function () use ($connectionId, $model): string {

            $database = DB::connection(StorageConnection::name());

            $database->statement(self::repeatableReadStatement($database->getDriverName()));
            $database->beginTransaction();

            Connection::query()->whereKey($connectionId)->get();
            $this->rowsOf($model);

            $this->signal(self::READ);
            $this->awaitSignal(self::WRITTEN);

            $status = app(ConnectionLifecycle::class)->delete(self::TENANT, $connectionId, Clients::browser())->status->value;

            $database->commit();

            return $status;
        };
    }

    /**
     * The writer: wait for the deleter's snapshot, write through the
     * connection, and signal once committed.
     *
     * @param  string  $writer
     * @return \Closure(): string
     */
    private function writer(string $writer): \Closure
    {
        $connectionId = $this->connection->id;

        return function () use ($connectionId, $writer): string {

            $this->awaitSignal(self::READ);

            try {
                return match ($writer) {
                    'link' => app(LinkStore::class)->create(
                        Connection::query()->findOrFail($connectionId),
                        new LinkSubject(self::ENTITY_ID, 'subject-1'),
                        new IdentityReference('user', '1'),
                        LinkOrigin::LINK_PURPOSE,
                        Clients::browser(),
                    )->status->value,
                    'key'         => app(KeyService::class)->addNext(self::TENANT, $connectionId, KeyUse::SP_SIGNING, Clients::browser())->status->value,
                    'certificate' => app(KeyService::class)->trustCertificate(self::TENANT, $connectionId, Certificates::distinct(0), Clients::browser())->status->value,
                    default       => app(DomainService::class)->claim(self::TENANT, $connectionId, 'example.com', Clients::browser())->status->value,
                };
            } finally {
                $this->signal(self::WRITTEN);
            }
        };
    }

    /**
     * How many rows of the model the connection has.
     *
     * @param  class-string<\SineMacula\Laravel\Sso\Models\SsoModel>  $model
     * @return int
     */
    private function rowsOf(string $model): int
    {
        return $model::query()->where('connection_id', $this->connection->id)->count();
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
