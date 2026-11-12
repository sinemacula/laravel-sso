<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Models\Connection;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the tenant-scoped connection lookup.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionFinder::class)]
final class ConnectionFinderTest extends TestCase
{
    use UsesConnections;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /**
     * Bind a fixed clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $this->clock);

        $this->usePackageTables();
    }

    /**
     * A connection is found for its own tenant only.
     *
     * @return void
     */
    public function testFindsAConnectionOnlyForItsTenant(): void
    {
        $finder     = new ConnectionFinder;
        $connection = $this->makeConnection(['tenant_id' => 'tenant-1']);

        self::assertSame($connection->id, $finder->find('tenant-1', $connection->id)?->id);
        self::assertNull($finder->find('tenant-2', $connection->id));
        self::assertNull($finder->find('tenant-1', '01jbunknownconnection00000'));
        self::assertNull($finder->find('tenant-1', ''));
        self::assertNull($finder->find('tenant-1', str_repeat('a', 27)));
    }

    /**
     * Tenant ids differing only in case or a trailing space are distinct
     * tenants, whatever the collation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMatchesTheTenantExactly(): void
    {
        $finder      = new ConnectionFinder;
        $connections = [];

        foreach (['acme', 'Acme', 'acme '] as $tenant) {
            $connections[$tenant] = $this->makeConnection(['tenant_id' => $tenant])->id;
        }

        foreach ($connections as $tenant => $id) {

            self::assertSame([$id], array_map(static fn (Connection $connection): string => $connection->id, $finder->forTenant($tenant)), $tenant);

            foreach ($connections as $other => $otherId) {

                $found  = $finder->find($tenant, $otherId)?->id;
                $locked = DB::transaction(static fn (): ?string => $finder->findForUpdate($tenant, $otherId)?->id);

                self::assertSame($tenant === $other ? $otherId : null, $found, "{$tenant} finding {$other}");
                self::assertSame($tenant === $other ? $otherId : null, $locked, "{$tenant} locking {$other}");
            }
        }
    }

    /**
     * A row matched only under the column's collation is treated as absent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTreatsARowOfATenantTheCollationCountsAsEqualAsAbsent(): void
    {
        $finder     = new ConnectionFinder;
        $connection = $this->makeConnection(['tenant_id' => 'acme']);

        // Stand in for a collation such as MySQL's `_ci`: the statement matches
        // `acme`, but the row it hands back records `Acme`.
        Connection::retrieved(static function (Connection $found): void {
            $found->setRawAttributes(['tenant_id' => 'Acme'] + $found->getAttributes(), true);
        });

        try {
            self::assertNull($finder->find('acme', $connection->id));
            self::assertNull(DB::transaction(static fn (): ?Connection => $finder->findForUpdate('acme', $connection->id)));
            self::assertSame([], $finder->forTenant('acme'));
        } finally {
            Event::forget('eloquent.retrieved: ' . Connection::class);
        }
    }

    /**
     * A tenant id of 255 bytes, the longest the table holds, finds its
     * connection.
     *
     * @return void
     */
    public function testFindsAConnectionOfTheLongestTenantId(): void
    {
        $tenant     = str_repeat('t', ConnectionFinder::MAX_TENANT_ID_LENGTH);
        $connection = $this->makeConnection(['tenant_id' => $tenant]);

        self::assertSame($connection->id, (new ConnectionFinder)->find($tenant, $connection->id)?->id);
        self::assertSame([$connection->id], array_map(static fn (Connection $found): string => $found->id, (new ConnectionFinder)->forTenant($tenant)));
    }

    /**
     * The locking lookup finds the same connection inside a transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testFindsAConnectionForUpdateInsideATransaction(): void
    {
        $finder     = new ConnectionFinder;
        $connection = $this->makeConnection();

        $found = DB::transaction(static fn () => $finder->findForUpdate('tenant-1', $connection->id));

        self::assertSame($connection->id, $found?->id);
        self::assertNull(DB::transaction(static fn () => $finder->findForUpdate('tenant-2', $connection->id)));
    }

    /**
     * Only the locking lookup locks the row; SQLite has no row lock, so it
     * compiles to a marker comment.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLocksTheRowOnlyForUpdate(): void
    {
        $finder     = new ConnectionFinder;
        $connection = $this->makeConnection();
        $database   = DB::connection(StorageConnection::name());

        if ($database->getDriverName() === 'sqlite') {
            $database->setQueryGrammar(new class ($database) extends SQLiteGrammar {
                /**
                 * Compile a lock for update to a marker comment.
                 *
                 * @param  \Illuminate\Database\Query\Builder  $query
                 * @param  bool|string  $value
                 * @return string
                 */
                #[\Override]
                protected function compileLock(Builder $query, $value): string
                {
                    return $value === true ? ' /* for update */' : '';
                }
            });
        }

        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        $database->listen(static function (QueryExecuted $query) use ($statements): void {
            $statements[] = strtolower($query->sql);
        });

        $finder->find('tenant-1', $connection->id);

        self::assertCount(1, $statements);
        self::assertStringNotContainsString('for update', $statements->getArrayCopy()[0]);

        $statements->exchangeArray([]);

        $database->transaction(static fn (): ?Connection => $finder->findForUpdate('tenant-1', $connection->id));

        self::assertCount(1, $statements);
        self::assertStringEndsWith('for update', rtrim($statements->getArrayCopy()[0], ' */'));
    }

    /**
     * A tenant's connections are listed oldest first, and no other tenant's.
     *
     * @return void
     */
    public function testListsATenantsConnectionsOldestFirst(): void
    {
        $first = $this->makeConnection();

        $this->clock->advance(60);

        $this->makeConnection(['tenant_id' => 'tenant-2']);
        $second = $this->makeConnection();

        self::assertSame([$first->id, $second->id], array_map(static fn ($connection): string => $connection->id, (new ConnectionFinder)->forTenant('tenant-1')));
        self::assertSame([], (new ConnectionFinder)->forTenant('tenant-3'));
    }

    /**
     * An empty or overlong tenant id is the application's mistake.
     *
     * @return void
     */
    public function testRefusesATenantIdTheTableCannotHold(): void
    {
        foreach (['', str_repeat('t', 256)] as $tenant) {

            try {
                (new ConnectionFinder)->find($tenant, 'x');
                self::fail('The tenant id was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A tenant id is 1 to 255 bytes.', $exception->getMessage());
            }
        }

        $this->expectException(\InvalidArgumentException::class);

        (new ConnectionFinder)->forTenant('');
    }

    /**
     * An id no connection can have, empty or overlong, is not found without a
     * query.
     *
     * @return void
     */
    public function testAnIdNoConnectionCanHaveIsNotFoundWithoutAQuery(): void
    {
        $finder     = new ConnectionFinder;
        $connection = $this->makeConnection();

        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use ($statements): void {
            $statements[] = $query->sql;
        });

        self::assertNull($finder->find('tenant-1', ''));
        self::assertNull($finder->find('tenant-1', $connection->id . 'x'));
        self::assertCount(0, $statements);
        self::assertSame($connection->id, $finder->find('tenant-1', $connection->id)?->id);
        self::assertCount(1, $statements);
    }
}
