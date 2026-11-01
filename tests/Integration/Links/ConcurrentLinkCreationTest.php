<?php

declare(strict_types = 1);

namespace Tests\Integration\Links;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Races link creations across processes, each with its own database connection,
 * on PostgreSQL and MySQL (SSO-8.4). Each creation locks the connection's row,
 * then counts the identity's links by a locking read, so creations in one
 * connection are serialised: two creations of one subject for different
 * identities make exactly one link, the other refused as
 * `subject_already_linked`; two subjects for one identity at a limit of one
 * make exactly one link, the other refused as `link_limit_reached`.
 *
 * Each race runs twice: plainly, and with every process inside a transaction of
 * its own that read the links table before the race began, so a read that
 * answered from that snapshot (MySQL's `REPEATABLE READ`) would fail it.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkStore::class)]
final class ConcurrentLinkCreationTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var string The issuer every subject is from. */
    private const string ISSUER = 'https://idp.example.com';

    /** @var ?\SineMacula\Laravel\Sso\Models\Connection The connection the links are made through. */
    private ?Connection $connection = null;

    /** @var string Directory the processes report their outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, bind a fixed clock,
     * create the tables and a connection, and make the directory the processes
     * report in.
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

        $this->createConnectionTables();
        $this->createFlowTables();

        $this->connection = $this->makeConnection(['enabled' => true]);

        $this->outcomes = sys_get_temp_dir() . '/link-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the outcomes and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (glob(($this->outcomes ?? sys_get_temp_dir() . '/none') . '/*') ?: [] as $file) {
            unlink($file);
        }

        if (isset($this->outcomes) && is_dir($this->outcomes)) {
            rmdir($this->outcomes);
        }

        if ($this->connection !== null) {
            $this->dropFlowTables();
            $this->dropConnectionTables();
        }

        parent::tearDown();
    }

    /**
     * Rows of `[inTransaction]`: each race plainly, and with every process
     * inside a transaction of its own.
     *
     * @return iterable<string, array{bool}>
     */
    public static function provideModes(): iterable
    {
        yield 'plainly' => [false];
        yield 'inside a caller\'s transaction' => [true];
    }

    /**
     * Two creations of one subject for different identities make exactly one
     * link; the other is `subject_already_linked`.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testExactlyOneOfTwoCreationsOfOneSubjectIsMade(bool $inTransaction): void
    {
        $outcomes = $this->race([['subject-1', '1'], ['subject-1', '2']], $inTransaction);
        $statuses = array_column($outcomes, 'status');

        sort($statuses);

        self::assertSame(['created', 'subject_already_linked'], $statuses, (string) json_encode($outcomes));

        $link    = Link::query()->sole();
        $created = array_values(array_filter($outcomes, static fn (array $outcome): bool => $outcome['status'] === 'created'));

        self::assertSame('subject-1', $link->subject);
        self::assertSame($created[0]['identity'] ?? null, $link->identity_id);
    }

    /**
     * Two subjects for one identity at the default limit of one make exactly
     * one link; the other is `link_limit_reached`.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testExactlyOneOfTwoSubjectsIsMadeAtTheLimit(bool $inTransaction): void
    {
        $outcomes = $this->race([['subject-1', '1'], ['subject-2', '1']], $inTransaction);
        $statuses = array_column($outcomes, 'status');

        sort($statuses);

        self::assertSame(['created', 'link_limit_reached'], $statuses, (string) json_encode($outcomes));
        self::assertSame('1', Link::query()->sole()->identity_id);
    }

    /**
     * Fork a process per subject and identity, have each create its link at the
     * same moment on a connection of its own, and collect what each reported.
     *
     * @param  list<array{0: string, 1: string}>  $creations
     * @param  bool  $inTransaction
     * @return list<array<string, mixed>>
     */
    private function race(array $creations, bool $inTransaction): array
    {
        $start = microtime(true) + 0.5;

        return $this->inProcesses(array_map(
            fn (array $creation): \Closure => fn (): array => $this->racer($start, $creation[0], $creation[1], $inTransaction),
            $creations,
        ));
    }

    /**
     * In a forked process: build the store, open a transaction that reads the
     * links table first when asked, wait for the start, create the link,
     * commit, and report the outcome and the identity.
     *
     * A process that reaches the start late, on a loaded machine, creates at
     * once rather than failing: the race is then less close, but every
     * assertion still holds.
     *
     * @param  float  $start
     * @param  string  $subject
     * @param  string  $identity
     * @param  bool  $inTransaction
     * @return array<string, mixed>
     */
    private function racer(float $start, string $subject, string $identity, bool $inTransaction): array
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app      = $this->app;
        $store    = $app->make(LinkStore::class);
        $database = DB::connection(StorageConnection::name());
        $through  = Connection::query()->findOrFail($this->connection?->id);

        if ($inTransaction) {
            $database->beginTransaction();
            Link::query()->count();
        }

        $wait = $start - microtime(true);

        if ($wait > 0) {
            usleep((int) ($wait * 1000000));
        }

        $creation = $store->create($through, new LinkSubject(self::ISSUER, $subject), new IdentityReference('user', $identity), LinkOrigin::LINK_PURPOSE);

        if ($inTransaction) {
            $database->commit();
        }

        return ['status' => $creation->status->value, 'identity' => $identity];
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
     * what it answered, or the error it threw, and end without running the
     * parent's shutdown.
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
            $outcome = ['status' => 'error', 'reason' => $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/{$process}", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }
}
