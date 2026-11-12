<?php

declare(strict_types = 1);

namespace Tests\Integration\Links;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\LinkRemoved;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Integration tests racing removals of one link across processes.
 *
 * The race also runs inside transactions that read the link first, to catch
 * answers from a `REPEATABLE READ` snapshot. Skipped on SQLite and without
 * `pcntl`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkService::class)]
final class ConcurrentLinkRemovalTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var int Processes racing to remove the link. */
    private const int REMOVERS = 2;

    /** @var string The table the revocation writes to, as an adapter writes its revoked sessions. */
    private const string REVOKED = 'example_raced_revoked_sessions';

    /** @var ?\SineMacula\Laravel\Sso\Models\Connection The connection the link was made through. */
    private ?Connection $connection = null;

    /** @var \SineMacula\Laravel\Sso\Models\Link The link every process races to remove. */
    private Link $link;

    /** @var string Directory the processes report their outcome and events in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, then set up the
     * revocation, a connection and its link, and the outcome directory.
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

        $this->outcomes = sys_get_temp_dir() . '/link-removal-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(SessionRevocation::class, self::writingRevocation());

        $this->usePackageTables();

        Schema::connection(StorageConnection::name())->create(self::REVOKED, static function (Blueprint $table): void {
            $table->id();
            $table->string('connection_id');
            $table->string('identity_id');
        });

        $this->connection = $this->makeConnection(['enabled' => true]);
        $this->link       = $this->makeLink($this->connection);

        $events = "{$this->outcomes}/events";

        Event::listen(LinkRemoved::class, static function () use ($events): void {
            file_put_contents($events, "removed\n", FILE_APPEND | LOCK_EX);
        });
    }

    /**
     * Remove the outcomes and drop the table the revocation writes to.
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
            Schema::connection(StorageConnection::name())->dropIfExists(self::REVOKED);
        }

        parent::tearDown();
    }

    /**
     * Rows of `[inTransaction]`.
     *
     * @return iterable<string, array{bool}>
     */
    public static function provideModes(): iterable
    {
        yield 'plainly' => [false];
        yield 'inside a caller\'s transaction' => [true];
    }

    /**
     * Exactly one racer removes the link; the other is `link_not_found`.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testExactlyOneOfTwoRemovalsOfOneLinkRemovesIt(bool $inTransaction): void
    {
        $outcomes = $this->race($inTransaction);
        $listed   = implode(', ', $outcomes);

        sort($outcomes);

        self::assertSame(['link_not_found', 'removed'], $outcomes, $listed);
        self::assertSame(0, Link::query()->count(), $listed);
        self::assertSame(
            [[(string) $this->connection?->id, '1']],
            DB::connection(StorageConnection::name())->table(self::REVOKED)->get()->map(static fn (object $row): array => [$row->connection_id, $row->identity_id])->all(),
            $listed,
        );
        self::assertSame("removed\n", (string) @file_get_contents("{$this->outcomes}/events"), $listed);
    }

    /**
     * Fork a process per removal and collect what each reported.
     *
     * @param  bool  $inTransaction
     * @return list<string>
     */
    private function race(bool $inTransaction): array
    {
        DB::disconnect();

        $start = microtime(true) + 0.5;
        $pids  = [];

        for ($process = 0; $process < self::REMOVERS; $process++) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $start, $inTransaction);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        $outcomes = [];

        for ($process = 0; $process < self::REMOVERS; $process++) {
            $outcomes[] = (string) file_get_contents("{$this->outcomes}/{$process}");
        }

        return $outcomes;
    }

    /**
     * In a forked process: wait for the start, remove the link, report the
     * outcome, and exit without the parent's shutdown.
     *
     * @param  int  $process
     * @param  float  $start
     * @param  bool  $inTransaction
     * @return never
     */
    private function runInChild(int $process, float $start, bool $inTransaction): never
    {
        try {
            DB::purge();
            DB::reconnect();
            DB::connection()->getPdo();

            $database = DB::connection(StorageConnection::name());

            if ($inTransaction) {
                $database->beginTransaction();
                Link::query()->whereKey($this->link->id)->get();
            }

            $wait = $start - microtime(true);

            if ($wait > 0) {
                usleep((int) ($wait * 1000000));
            }

            $result = app(LinkService::class)->remove(new IdentityReference('user', '1'), $this->link->id, Clients::browser());

            if ($inTransaction) {
                $database->commit();
            }

            $outcome = $result->isRemoved() ? 'removed' : (string) $result->reason?->value;
        } catch (\Throwable $e) {
            $outcome = 'error: ' . $e::class . ': ' . $e->getMessage();
        }

        file_put_contents("{$this->outcomes}/{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * A revocation that writes through the storage connection, so it commits
     * with the removal.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SessionRevocation
     */
    private static function writingRevocation(): SessionRevocation
    {
        return new readonly class (self::REVOKED) implements SessionRevocation {
            /**
             * Constructor.
             *
             * @param  string  $table
             */
            public function __construct(

                /** The table it writes to. */
                private string $table,
            ) {}

            /**
             * Write the connection and identity revoked for.
             *
             * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
             * @return void
             */
            #[\Override]
            public function revoke(RevocationScope $scope): void
            {
                DB::connection(StorageConnection::name())->table($this->table)->insert([
                    'connection_id' => (string) $scope->connectionId,
                    'identity_id'   => (string) $scope->identity?->id,
                ]);
            }
        };
    }
}
