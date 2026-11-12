<?php

declare(strict_types = 1);

namespace Tests\Integration\Connections;

use Illuminate\Database\Connection as DatabaseConnection;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\SubjectMigration;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Enforcement\RecordingRevocation;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Races a subject migration against a link created after its disposition was
 * prepared, across processes. Skipped on SQLite and without `pcntl`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectMigration::class)]
#[CoversClass(LinkStore::class)]
final class ConcurrentSubjectMigrationTest extends TestCase
{
    use UsesFlowTables;

    /** @var string The tenant the connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var string The issuer the connection trusts, and its links were made with. */
    private const string ISSUER = 'https://idp.example.com';

    /** @var string The issuer the migration moves the connection to. */
    private const string NEW_ISSUER = 'https://login.example.com';

    /** @var array<string, string> The settings of a complete OIDC connection. */
    private const array OIDC = [
        'issuer'                 => self::ISSUER,
        'authorization_endpoint' => 'https://idp.example.com/authorize',
        'token_endpoint'         => 'https://idp.example.com/token',
        'jwks_uri'               => 'https://idp.example.com/jwks',
        'client_id'              => 'client-123',
    ];

    /** @var float How long, in seconds, a process waits for the other before it gives up. */
    private const float DEADLINE_SECONDS = 30.0;

    /** @var string What a process reports for a serialisation failure. */
    private const string SERIALIZATION_FAILURE = 'serialization_failure';

    /** @var ?\SineMacula\Laravel\Sso\Models\Connection The connection migrated and linked through. */
    private ?Connection $connection = null;

    /** @var array<string, string> The connection's links before the race, by name, as ids. */
    private array $links = [];

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, bind the collaborators,
     * and seed an OIDC connection with three links.
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

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(SessionRevocation::class, new RecordingRevocation);

        config()->set('sso.features.oidc', true);

        $this->usePackageTables();

        $created = $this->service()->create(self::TENANT, 'oidc', 'Acme', Clients::browser(), self::OIDC);

        $this->connection = Connection::query()->whereKey((string) $created->connection?->id)->sole();

        foreach (['first' => '1', 'second' => '2', 'third' => '3'] as $name => $identity) {
            $this->links[$name] = $this->makeLink($this->connection, $name . '-subject', ['identity_id' => $identity])->id;
        }

        $this->outcomes = sys_get_temp_dir() . '/migration-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the signals and outcomes.
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

        parent::tearDown();
    }

    /**
     * Rows of `[repeatableRead, readFirst]`: the migration's isolation, and
     * whether it reads the tables first in its own transaction.
     *
     * @return iterable<string, array{0: bool, 1: bool}>
     */
    public static function provideModes(): iterable
    {
        foreach (['at the default isolation' => false, 'under repeatable read' => true] as $isolation => $repeatableRead) {
            foreach (['plainly' => false, 'after a read in a caller\'s transaction' => true] as $mode => $readFirst) {
                yield "{$isolation}, {$mode}" => [$repeatableRead, $readFirst];
            }
        }
    }

    /**
     * A link created mid-migration is never left behind: `links_unaccounted`,
     * or a serialisation failure on PostgreSQL.
     *
     * @param  bool  $repeatableRead
     * @param  bool  $readFirst
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testALinkCreatedWhileTheMigrationWaitsIsNeverLeftBehind(bool $repeatableRead, bool $readFirst): void
    {
        $signal                = "{$this->outcomes}/creator-locked";
        [$creator, $migration] = $this->inProcesses([
            fn (): array => $this->createLink($signal),
            fn (): array => $this->migrate($signal, $repeatableRead, $readFirst),
        ]);
        $reported = (string) json_encode([$creator, $migration]);
        $accepted = ['refused:links_unaccounted'];

        if ($repeatableRead && DB::connection()->getDriverName() === 'pgsql') {
            $accepted[] = self::SERIALIZATION_FAILURE;
        }

        self::assertSame('created', $creator['status'] ?? null, $reported);
        self::assertTrue($creator['sawWaiter'] ?? false, 'The migration never waited on the lock: ' . $reported);
        self::assertContains($migration['status'] ?? null, $accepted, $reported);

        self::assertSame(self::ISSUER, Connection::query()->findOrFail($this->connection?->id)->settings['issuer'] ?? null, $reported);
        self::assertSame(
            ['1' => 'first-subject', '2' => 'second-subject', '3' => 'third-subject', '9' => 'late-subject'],
            Link::query()->where('connection_id', $this->connection?->id)->orderBy('identity_id')->pluck('subject', 'identity_id')->all(),
            $reported,
        );
    }

    /**
     * In a child: create a link inside a transaction, holding the lock until
     * the migration waits on it.
     *
     * @param  string  $signal
     * @return array<string, mixed>
     */
    private function createLink(string $signal): array
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app      = $this->app;
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        $creation = $app->make(LinkStore::class)->create(
            Connection::query()->findOrFail($this->connection?->id),
            new LinkSubject(self::ISSUER, 'late-subject'),
            new IdentityReference('user', '9'),
            LinkOrigin::LINK_PURPOSE,
            Clients::browser(),
        );
        $sawWaiter = self::hasAWaiterOnceSignalled($database, $signal);

        $database->commit();

        return ['status' => $creation->status->value, 'sawWaiter' => $sawWaiter];
    }

    /**
     * In a child: wait for the creator, then migrate with the disposition
     * prepared before the race.
     *
     * @param  string  $signal
     * @param  bool  $repeatableRead
     * @param  bool  $readFirst
     * @return array<string, mixed>
     */
    private function migrate(string $signal, bool $repeatableRead, bool $readFirst): array
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app      = $this->app;
        $database = DB::connection(StorageConnection::name());

        if ($repeatableRead) {
            $database->statement(self::repeatableReadStatement($database->getDriverName()));
        }

        if ($readFirst) {
            $database->beginTransaction();
            Connection::query()->get();
            Link::query()->get();
        }

        self::await($signal);

        $result = $app->make(SubjectMigration::class)->migrate(
            self::TENANT,
            (string) $this->connection?->id,
            ['settings' => ['issuer' => self::NEW_ISSUER]],
            [$this->links['first'] => ['first-new']],
            [$this->links['second'], $this->links['third']],
            Clients::browser(),
        );

        if ($readFirst) {
            $database->commit();
        }

        return ['status' => self::statusOf($result)];
    }

    /**
     * A migration result's status, and the reason of a refusal.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionResult  $result
     * @return string
     */
    private static function statusOf(ConnectionResult $result): string
    {
        return $result->reason === null ? $result->status->value : $result->status->value . ':' . $result->reason->value;
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
     * Wait until the other process has signalled, or the deadline passes.
     *
     * @param  string  $signal
     * @return void
     */
    private static function await(string $signal): void
    {
        $deadline = microtime(true) + self::DEADLINE_SECONDS;

        while (!file_exists($signal) && microtime(true) < $deadline) {
            usleep(5000);
        }
    }

    /**
     * Signal, then poll until another session waits on a lock this one holds;
     * answer whether one did.
     *
     * @param  \Illuminate\Database\Connection  $database
     * @param  string  $signal
     * @return bool
     *
     * @throws \LogicException
     */
    private static function hasAWaiterOnceSignalled(DatabaseConnection $database, string $signal): bool
    {
        touch($signal);

        $query    = self::waitersQuery($database->getDriverName());
        $deadline = microtime(true) + self::DEADLINE_SECONDS;

        do {

            $row = $database->selectOne($query, [], false);

            if ($row instanceof \stdClass && (int) ($row->waiting ?? 0) > 0) {
                return true;
            }

            usleep(10000);
        } while (microtime(true) < $deadline);

        return false;
    }

    /**
     * The query that counts the sessions waiting on a lock the current session
     * holds.
     *
     * @param  string  $driver
     * @return string
     *
     * @throws \LogicException
     */
    private static function waitersQuery(string $driver): string
    {
        return match ($driver) {
            'pgsql' => 'select count(*) as waiting from (select distinct pid from pg_locks where not granted) as waits where pg_backend_pid() = any(pg_blocking_pids(waits.pid))',
            'mysql' => 'select count(*) as waiting from performance_schema.data_lock_waits where BLOCKING_THREAD_ID = ps_current_thread_id()',
            default => throw new \LogicException(sprintf('No query finds the sessions waiting on a lock on [%s].', $driver)),
        };
    }

    /**
     * Fork a process per body, each on its own connection, and collect what
     * each reported, in order.
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
     * In a child: open its own connection, run the body, report the outcome,
     * and exit without the parent's shutdown.
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
     * SQLSTATE 40001 on PostgreSQL, where a deadlock is 40P01; inside a
     * transaction Laravel wraps it in a `DeadlockException`.
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
     * The management helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionService
     */
    private function service(): ConnectionService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ConnectionService::class);
    }
}
