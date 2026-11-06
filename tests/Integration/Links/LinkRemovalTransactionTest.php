<?php

declare(strict_types = 1);

namespace Tests\Integration\Links;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\LinkRemoved;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkEvents;
use SineMacula\Laravel\Sso\Links\LinkResult;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Enforcement\FailingRevocation;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Integration tests, on a real database, that a link's removal and the session
 * revocation it needs commit or roll back together (SSO-4.5, SSO-10.5, decision
 * D5): a revocation that throws leaves the link, reports nothing and
 * propagates; one that writes through the storage connection commits with the
 * removal; and inside a transaction the application opened, a rollback undoes
 * both though the helper succeeded, with nothing reported, while a commit
 * reports the removal only then.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkService::class)]
#[CoversClass(LinkEvents::class)]
final class LinkRemovalTransactionTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The table the revocation writes to, as an adapter writes its revoked sessions. */
    private const string REVOKED = 'example_revoked_link_sessions';

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the link was made through. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The identity whose link is removed. */
    private IdentityReference $identity;

    /** @var \SineMacula\Laravel\Sso\Models\Link The link removed. */
    private Link $link;

    /**
     * Bind a fixed clock and a fresh caller, create the tables, a connection, a
     * link and the revocation's table, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $this->usePackageTables();

        Schema::connection(StorageConnection::name())->create(self::REVOKED, static function (Blueprint $table): void {
            $table->id();
            $table->string('connection_id');
            $table->string('identity_id');
        });

        $this->connection = $this->makeConnection(['enabled' => true]);
        $this->identity   = new IdentityReference('user', '1');
        $this->link       = $this->makeLink($this->connection);

        $this->startRecordingEvents();
    }

    /**
     * Drop the table the revocation writes to.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::connection(StorageConnection::name())->dropIfExists(self::REVOKED);

        parent::tearDown();
    }

    /**
     * A revocation that throws rolls the removal back: the link stays, nothing
     * is reported, and the exception propagates.
     *
     * @return void
     */
    public function testAFailingRevocationRollsTheRemovalBack(): void
    {
        $revocation = new FailingRevocation;

        $this->app?->instance(SessionRevocation::class, $revocation);

        try {
            $this->remove();
            self::fail('The removal succeeded.');
        } catch (\RuntimeException $exception) {
            self::assertSame(FailingRevocation::MESSAGE, $exception->getMessage());
        }

        self::assertSame(1, $revocation->calls());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertSame($this->link->id, Link::query()->sole()->id);
        $this->assertNoEvents();
    }

    /**
     * A revocation that writes and then throws leaves neither its write nor the
     * removal.
     *
     * @return void
     */
    public function testAWritingRevocationThatFailsLeavesNeither(): void
    {
        $this->bindWritingRevocation(true);

        try {
            $this->remove();
            self::fail('The removal succeeded.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The sessions could not be revoked.', $exception->getMessage());
        }

        self::assertSame(1, Link::query()->count());
        self::assertSame([], $this->revoked());
        $this->assertNoEvents();
    }

    /**
     * A revocation that writes and succeeds commits with the removal, which is
     * then reported once.
     *
     * @return void
     */
    public function testAWritingRevocationThatSucceedsCommitsWithTheRemoval(): void
    {
        $this->bindWritingRevocation(false);

        self::assertTrue($this->remove()->isRemoved());
        self::assertSame(0, Link::query()->count());
        self::assertSame([[$this->connection->id, '1']], $this->revoked());
        $this->assertEventSequence([LinkRemoved::class]);
    }

    /**
     * Inside a transaction the application opened, the removal and the
     * revocation's write are undone by its rollback, though the helper
     * succeeded, and nothing is reported.
     *
     * @return void
     */
    public function testAnApplicationRollbackUndoesTheRemoval(): void
    {
        $this->bindWritingRevocation(false);

        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        self::assertTrue($this->remove()->isRemoved());
        self::assertSame(0, Link::query()->count());
        $this->assertNoEvents();

        $database->rollBack();

        self::assertSame($this->link->id, Link::query()->sole()->id);
        self::assertSame([], $this->revoked());
        $this->assertNoEvents();
    }

    /**
     * Inside a transaction the application opened, the removal is reported only
     * once it commits.
     *
     * @return void
     */
    public function testAnApplicationCommitReportsTheRemoval(): void
    {
        $this->bindWritingRevocation(false);

        DB::connection(StorageConnection::name())->transaction(function (): void {

            self::assertTrue($this->remove()->isRemoved());

            $this->assertNoEvents();
        });

        self::assertSame(0, Link::query()->count());
        self::assertCount(1, $this->revoked());
        $this->assertEventSequence([LinkRemoved::class]);
    }

    /**
     * Remove the identity's link.
     *
     * @return \SineMacula\Laravel\Sso\Links\LinkResult
     */
    private function remove(): LinkResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(LinkService::class)->remove($this->identity, $this->link->id);
    }

    /**
     * Bind a revocation that records the scope's connection and identity in the
     * revocation's table, through the storage connection, and then throws when
     * asked to.
     *
     * @param  bool  $fails
     * @return void
     */
    private function bindWritingRevocation(bool $fails): void
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
             * Write the connection and identity revoked for, then fail when
             * told to.
             *
             * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function revoke(RevocationScope $scope): void
            {
                DB::connection(StorageConnection::name())->table($this->table)->insert([
                    'connection_id' => (string) $scope->connectionId,
                    'identity_id'   => (string) $scope->identity?->id,
                ]);

                if ($this->fails) {
                    throw new \RuntimeException('The sessions could not be revoked.');
                }
            }
        });
    }

    /**
     * Each connection and identity the revocation wrote, in order.
     *
     * @return list<array{0: string, 1: string}>
     */
    private function revoked(): array
    {
        $rows = DB::connection(StorageConnection::name())->table(self::REVOKED)->orderBy('id')->get(['connection_id', 'identity_id'])->all();

        return array_values(array_map(static fn (\stdClass $row): array => [(string) $row->connection_id, (string) $row->identity_id], $rows));
    }
}
