<?php

declare(strict_types = 1);

namespace Tests\Integration\Linking;

use Illuminate\Database\Connection as DatabaseConnection;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Races the provisioning helper across processes, each with its own database
 * connection, on PostgreSQL and MySQL (SSO-8.4, SSO-8.6, SSO-11.3): against a
 * second racer provisioning the same subject, for the same identity or another;
 * against a connection's disable and a trust change, each ordered both ways;
 * and against an explicit link's creation. And two first sign-ins through two
 * connections, each provisioning a new identity in a listener transaction that
 * retries: on MySQL their empty-range locking reads take gap locks, so their
 * inserts deadlock and the one rolled back retries; both provision.
 *
 * The order is forced with signal files, never with timing, and a barrier that
 * times out fails loudly. Every race runs with each racer plain and inside a
 * transaction of its own at `REPEATABLE READ` that read the connection, its
 * requests and its links first: a helper in the listener's transaction, opened
 * once the result is offered; a changer in one opened before the flow runs. So
 * each locking read must see what another committed rather than its snapshot on
 * MySQL. On PostgreSQL such a racer whose snapshot predates what it waits on
 * fails to serialise instead (SQLSTATE `40001`): that is a safe end, accepted
 * there alone, and nothing it did stands. A changer in such a transaction
 * always
 * ends so against a helper, since the flow it would void ran after its snapshot;
 * the changes race one racer in a transaction at a time as well, so that a
 * helper's own stale transaction meets what a change committed on PostgreSQL
 * too.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProvisioningHelper::class)]
final class ConcurrentProvisioningTest extends LinkingTestCase
{
    /** @var string What a racer reports when it failed to serialise. */
    private const string SERIALIZATION = 'serialization';

    /** @var string The issuer the trust change moves the connection to. */
    private const string NEW_ISSUER = 'https://idp.example.com/moved';

    /** @var float Seconds a racer waits for the other's signal before it gives up. */
    private const float SIGNAL_SECONDS = 10.0;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference Another identity than the person. */
    private IdentityReference $other;

    /** @var string Directory the processes signal and report in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, make the result unmatched
     * by any verified domain, bind fresh authentication and a limiter that
     * allows every attempt, and make the directory the processes report in.
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

        $this->matcher->match = LinkEmailMatch::none();
        $this->other          = new IdentityReference('App\Models\User', '8');

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(AttemptLimiter::class, new readonly class implements AttemptLimiter {
            /**
             * Allow every attempt.
             *
             * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject  $subject
             * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptResult
             */
            #[\Override]
            public function attempt(AttemptSubject $subject): AttemptResult
            {
                unset($subject);

                return AttemptResult::allowed();
            }
        });

        $this->outcomes = sys_get_temp_dir() . '/provisioning-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the signals and outcomes, and drop the tables.
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
     * Rows of `[inTransaction]`: each race plainly, and with every racer inside
     * a transaction of its own that read first.
     *
     * @return iterable<string, array{bool}>
     */
    public static function provideModes(): iterable
    {
        yield 'plainly' => [false];
        yield 'inside a transaction that read first' => [true];
    }

    /**
     * Two racers provisioning one subject for two identities make one link: the
     * other is `subject_already_linked`, and its final continuation resolves to
     * the winner's identity.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testTwoIdentitiesWithOneSubjectMakeOneLink(bool $inTransaction): void
    {
        $this->assertOneOfTwoLinks($inTransaction, $this->person, $this->other);
    }

    /**
     * The same race for one identity: the subject is judged before the limit,
     * so the second is `subject_already_linked`, not a reached limit.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testTwoRacersProvisioningOneIdentityMakeOneLink(bool $inTransaction): void
    {
        $this->assertOneOfTwoLinks($inTransaction, $this->person, $this->person);
    }

    /**
     * Rows of `[whether the helper is in a transaction that read first, whether
     * the changer is]`.
     *
     * @return iterable<string, array{0: bool, 1: bool}>
     */
    public static function provideRacers(): iterable
    {
        yield 'both plainly' => [false, false];
        yield 'the helper in its own that read first' => [true, false];
        yield 'the changer in its own that read first' => [false, true];
        yield 'each in its own that read first' => [true, true];
    }

    /**
     * A disable committed before the helper refuses it, and the final
     * continuation in its turn.
     *
     * @param  bool  $helperInTransaction
     * @param  bool  $changerInTransaction
     * @return void
     */
    #[DataProvider('provideRacers')]
    public function testAHelperAfterADisableIsRefused(bool $helperInTransaction, bool $changerInTransaction): void
    {
        $this->assertChangeFirst($helperInTransaction, $changerInTransaction, 'disabled', fn (): string => $this->disabled());
    }

    /**
     * A disable that waited for the helper leaves its link, and refuses the
     * final continuation.
     *
     * @param  bool  $helperInTransaction
     * @param  bool  $changerInTransaction
     * @return void
     */
    #[DataProvider('provideRacers')]
    public function testADisableAfterTheHelperLeavesTheLinkAndRefusesTheFinish(bool $helperInTransaction, bool $changerInTransaction): void
    {
        [$helper, $changer] = $this->helperFirst($helperInTransaction, $changerInTransaction, fn (): string => $this->disabled());

        self::assertSame('created', $helper['helper'] ?? null, self::reported($helper, $changer));
        self::assertSame(1, Link::query()->count());

        if (self::serializes($changer, $changerInTransaction)) {
            self::assertSame('completed', $helper['completion'] ?? null, self::reported($helper, $changer));
            self::assertTrue($this->connection->refresh()->enabled);

            return;
        }

        self::assertSame('disabled', $changer['status'] ?? null, self::reported($helper, $changer));
        self::assertSame(['failed', 'connection_unavailable'], [$helper['completion'] ?? null, $helper['reason'] ?? null], self::reported($helper, $changer));
    }

    /**
     * A trust change committed before the helper refuses it, and the final
     * continuation in its turn.
     *
     * @param  bool  $helperInTransaction
     * @param  bool  $changerInTransaction
     * @return void
     */
    #[DataProvider('provideRacers')]
    public function testAHelperAfterATrustChangeIsRefused(bool $helperInTransaction, bool $changerInTransaction): void
    {
        $this->assertChangeFirst($helperInTransaction, $changerInTransaction, 'updated', fn (): string => $this->trustChanged());
    }

    /**
     * A trust change of what subjects mean that waited for the helper is
     * refused, since the connection now holds a link; the flow finishes.
     *
     * @param  bool  $helperInTransaction
     * @param  bool  $changerInTransaction
     * @return void
     */
    #[DataProvider('provideRacers')]
    public function testATrustChangeAfterTheHelperIsRefusedByItsLink(bool $helperInTransaction, bool $changerInTransaction): void
    {
        [$helper, $changer] = $this->helperFirst($helperInTransaction, $changerInTransaction, fn (): string => $this->trustChanged());

        self::assertSame('created', $helper['helper'] ?? null, self::reported($helper, $changer));
        self::assertSame('completed', $helper['completion'] ?? null, self::reported($helper, $changer));
        self::assertSame(1, Link::query()->count());

        self::assertSame(VerifyingDriver::ISSUER, $this->connection->refresh()->settings['issuer'] ?? null);

        if (self::serializes($changer, $changerInTransaction)) {
            return;
        }

        self::assertSame('refused', $changer['status'] ?? null, self::reported($helper, $changer));
    }

    /**
     * The helper raced against an explicit link's creation makes one link, and
     * the final continuation resolves to whichever identity holds it.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testTheHelperAgainstAnExplicitLinkMakesOneLink(bool $inTransaction): void
    {
        [$state, $start] = $this->startedFlow();

        $offered = "{$this->outcomes}/offered";
        $ready   = "{$this->outcomes}/explicit-ready";

        [$helper, $explicit] = $this->inProcesses([
            fn (): array => $this->provisioned($state, $this->person, $inTransaction, static function () use ($offered, $ready): void {
                touch($offered);
                self::await($ready);
            }),
            fn (): array => $this->explicitLink($inTransaction, $offered, $ready),
        ]);

        $link = Link::query()->sole();

        if ($link->identity_id === $this->person->id) {
            $this->assertHelperWon($helper, $explicit, $start, $inTransaction);

            return;
        }

        $this->assertExplicitLinkWon($helper, $explicit, $start, $inTransaction);
    }

    /**
     * Two first sign-ins through two connections, each listener provisioning a
     * new identity in a transaction at `REPEATABLE READ` it retries, both
     * provision once both have read the identity's links: on MySQL the gap
     * locks of those reads deadlock the inserts, and exactly one retries.
     *
     * @return void
     */
    public function testTwoFirstSignInsThatDeadlockBothProvisionOnRetry(): void
    {
        $first  = $this->connection;
        $second = $this->makeConnection([
            'protocol'          => VerifyingDriver::NAME,
            'enabled'           => true,
            'settings'          => ['issuer' => VerifyingDriver::ISSUER],
            'attribute_mapping' => ['email' => 'mail'],
        ]);

        [$firstState] = $this->startedFlow();

        $this->connection = $second;

        [$secondState] = $this->startedFlow();

        $this->connection = $first;

        $outcomes = $this->inProcesses([
            fn (): array => $this->retried($firstState, $first, $this->person, 0, 1),
            fn (): array => $this->retried($secondState, $second, $this->other, 1, 0),
        ]);

        $reported = self::reported(...$outcomes);

        foreach ($outcomes as $outcome) {
            self::assertSame('created', $outcome['helper'] ?? null, $reported);
            self::assertSame('completed', $outcome['completion'] ?? null, $reported);
        }

        self::assertSame(2, Link::query()->count(), $reported);
        self::assertSame(DB::connection()->getDriverName() === 'mysql' ? 3 : 2, array_sum(array_column($outcomes, 'attempts')), $reported);
    }

    /**
     * The helper made the link: the explicit link was refused, or failed to
     * serialise, and the completion resolved to the helper's identity.
     *
     * @param  array<string, mixed>  $helper
     * @param  array<string, mixed>  $explicit
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  bool  $inTransaction
     * @return void
     */
    private function assertHelperWon(array $helper, array $explicit, StartResult $start, bool $inTransaction): void
    {
        $reported = self::reported($helper, $explicit);

        self::assertSame(['created', 'completed'], [$helper['helper'] ?? null, $helper['completion'] ?? null], $reported);
        self::assertSame(LinkOrigin::PROVISIONING, Link::query()->sole()->provenance);
        self::assertSame($this->person->id, $this->redeemed($helper, $start)->linkedIdentity?->id);

        if (self::serializes($explicit, $inTransaction)) {
            return;
        }

        self::assertSame('subject_already_linked', $explicit['status'] ?? null, $reported);
    }

    /**
     * The explicit link was made: the helper was refused, or failed to
     * serialise, and the completion resolved to the explicit link's identity.
     *
     * @param  array<string, mixed>  $helper
     * @param  array<string, mixed>  $explicit
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  bool  $inTransaction
     * @return void
     */
    private function assertExplicitLinkWon(array $helper, array $explicit, StartResult $start, bool $inTransaction): void
    {
        $reported = self::reported($helper, $explicit);
        $link     = Link::query()->sole();

        self::assertSame($this->other->id, $link->identity_id, $reported);
        self::assertSame('created', $explicit['status'] ?? null, $reported);
        self::assertSame(LinkOrigin::LINK_PURPOSE, $link->provenance);

        if (self::serializes($helper, $inTransaction)) {
            return;
        }

        self::assertSame(['subject_already_linked', 'completed'], [$helper['helper'] ?? null, $helper['completion'] ?? null], $reported);
        self::assertSame($this->other->id, $this->redeemed($helper, $start)->linkedIdentity?->id);
    }

    /**
     * Race two provisioning racers, both offered before either asks the helper,
     * and assert one made the link and the other resolved to it.
     *
     * @param  bool  $inTransaction
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $first
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $second
     * @return void
     */
    private function assertOneOfTwoLinks(bool $inTransaction, IdentityReference $first, IdentityReference $second): void
    {
        [$firstState, $firstStart]   = $this->startedFlow();
        [$secondState, $secondStart] = $this->startedFlow();

        $barrier = fn (int $mine, int $peers): \Closure => function () use ($mine, $peers): void {
            touch("{$this->outcomes}/offered-{$mine}");
            self::await("{$this->outcomes}/offered-{$peers}");
        };

        $outcomes = $this->inProcesses([
            fn (): array => $this->provisioned($firstState, $first, $inTransaction, $barrier(0, 1)),
            fn (): array => $this->provisioned($secondState, $second, $inTransaction, $barrier(1, 0)),
        ]);

        $reported = self::reported(...$outcomes);
        $racers   = [[$outcomes[0], $firstStart, $first], [$outcomes[1], $secondStart, $second]];
        $winning  = array_values(array_filter($racers, static fn (array $racer): bool => ($racer[0]['helper'] ?? null) === 'created'));

        self::assertCount(1, $winning, $reported);

        [$winner, $winnerStart, $identity] = $winning[0];

        $losing = array_values(array_filter($racers, static fn (array $racer): bool => $racer[0] !== $winner));
        $link   = Link::query()->sole();

        self::assertSame($identity->id, $link->identity_id, $reported);
        self::assertSame('completed', $winner['completion'] ?? null, $reported);
        self::assertSame($link->id, $this->redeemed($winner, $winnerStart)->linkId, $reported);

        foreach ($losing as [$loser, $loserStart]) {

            if (self::serializes($loser, $inTransaction)) {
                continue;
            }

            self::assertSame('subject_already_linked', $loser['helper'] ?? null, $reported);
            self::assertSame('completed', $loser['completion'] ?? null, $reported);

            $redeemed = $this->redeemed($loser, $loserStart);

            self::assertSame($identity->id, $redeemed->linkedIdentity?->id, $reported);
            self::assertSame($link->id, $redeemed->linkId, $reported);
        }
    }

    /**
     * Race a change that commits before the helper asks, and assert exactly how
     * each ends. On PostgreSQL a changer in a transaction fails to serialise on
     * the request the flow changed after its snapshot, and the helper then
     * stands alone. Otherwise the change commits: a helper in a transaction on
     * PostgreSQL fails to serialise on the connection's row, with nothing made,
     * and any other helper is refused, and the final continuation in its turn.
     *
     * @param  bool  $helperInTransaction
     * @param  bool  $changerInTransaction
     * @param  string  $status
     * @param  \Closure(): string  $change
     * @return void
     */
    private function assertChangeFirst(bool $helperInTransaction, bool $changerInTransaction, string $status, \Closure $change): void
    {
        [$state] = $this->startedFlow();

        $read    = "{$this->outcomes}/changer-read";
        $offered = "{$this->outcomes}/offered";
        $changed = "{$this->outcomes}/changed";

        [$helper, $changer] = $this->inProcesses([
            function () use ($state, $helperInTransaction, $read, $offered, $changed): array {
                self::await($read);

                return $this->provisioned($state, $this->person, $helperInTransaction, static function () use ($offered, $changed): void {
                    touch($offered);
                    self::await($changed);
                });
            },
            fn (): array => $this->changing($changerInTransaction, $read, $changed, static function () use ($offered, $change): string {
                self::await($offered);

                return $change();
            }),
        ]);

        $reported   = self::reported($helper, $changer);
        $isPostgres = DB::connection()->getDriverName() === 'pgsql';

        if ($isPostgres && $changerInTransaction) {
            self::assertTrue(self::serializes($changer, $changerInTransaction), $reported);
            self::assertSame(['created', 'completed'], [$helper['helper'] ?? null, $helper['completion'] ?? null], $reported);
            self::assertSame(1, Link::query()->count());

            return;
        }

        self::assertSame($status, $changer['status'] ?? null, $reported);
        self::assertSame(0, Link::query()->count(), $reported);

        if ($isPostgres && $helperInTransaction) {
            self::assertTrue(self::serializes($helper, $helperInTransaction), $reported);

            return;
        }

        self::assertSame('request_unavailable', $helper['helper'] ?? null, $reported);
        self::assertSame(['failed', 'connection_unavailable'], [$helper['completion'] ?? null, $helper['reason'] ?? null], $reported);
    }

    /**
     * Race a change that goes on only once the helper has linked, and let the
     * final continuation run only once the change ended.
     *
     * @param  bool  $helperInTransaction
     * @param  bool  $changerInTransaction
     * @param  \Closure(): string  $change
     * @return array{0: array<string, mixed>, 1: array<string, mixed>}
     */
    private function helperFirst(bool $helperInTransaction, bool $changerInTransaction, \Closure $change): array
    {
        [$state] = $this->startedFlow();

        $read     = "{$this->outcomes}/changer-read";
        $linked   = "{$this->outcomes}/linked";
        $changing = "{$this->outcomes}/changing";
        $changed  = "{$this->outcomes}/changed";

        $outcomes = $this->inProcesses([
            function () use ($state, $helperInTransaction, $read, $linked, $changing, $changed): array {
                self::await($read);

                return $this->provisioned(
                    $state,
                    $this->person,
                    $helperInTransaction,
                    null,
                    static function () use ($linked, $changing): void {
                        touch($linked);
                        self::await($changing);
                    },
                    static function () use ($changed): void {
                        self::await($changed);
                    },
                );
            },
            fn (): array => $this->changing($changerInTransaction, $read, $changed, static function () use ($linked, $changing, $change): string {
                self::await($linked);
                touch($changing);

                return $change();
            }),
        ]);

        return [$outcomes[0], $outcomes[1]];
    }

    /**
     * In a forked process: complete the flow, with a listener that opens its
     * transaction and reads first when asked; runs what comes before the
     * helper; asks the helper; runs what holds the transaction open; commits a
     * link or rolls a refusal back; and runs what comes before the final
     * continuation. Report what the helper answered, how the completion ended
     * and its code.
     *
     * @param  string  $state
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  bool  $inTransaction
     * @param  ?\Closure(): void  $before
     * @param  ?\Closure(): void  $holding
     * @param  ?\Closure(): void  $after
     * @return array<string, mixed>
     */
    private function provisioned(
        string $state,
        IdentityReference $identity,
        bool $inTransaction,
        ?\Closure $before = null,
        ?\Closure $holding = null,
        ?\Closure $after = null,
    ): array {
        $status = null;

        Event::listen(ResultUnlinked::class, function (ResultUnlinked $event) use ($identity, $inTransaction, $before, $holding, $after, &$status): void {

            $database = DB::connection(StorageConnection::name());

            if ($inTransaction) {
                $this->openAndRead($database);
            }

            self::runIfGiven($before);

            $answer = app(ProvisioningHelper::class)->link($event->grant, $event->result, $identity, Clients::browser());
            $status = $answer->status->value;

            self::runIfGiven($holding);

            if ($inTransaction) {
                $answer->isCreated() ? $database->commit() : $database->rollBack();
            }

            self::runIfGiven($after);
        });

        $completion = $this->completion($state);

        return [
            'helper'     => $status,
            'completion' => $completion->status->value,
            'reason'     => $completion->reason?->value,
            'code'       => $completion->handoff?->code->reveal(),
        ];
    }

    /**
     * In a forked process: complete the flow on the connection, its listener
     * provisioning the identity in a transaction at `REPEATABLE READ` that it
     * retries up to three times, and the link limit, asked once the identity's
     * links are read, waiting the first time for the peer to have read too.
     * Report what the helper last answered, how often the listener tried, and
     * how the completion ended.
     *
     * @param  string  $state
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  int  $mine
     * @param  int  $peer
     * @return array<string, mixed>
     */
    private function retried(string $state, Connection $connection, IdentityReference $identity, int $mine, int $peer): array
    {
        $this->connection = $connection;
        $status           = null;
        $attempts         = 0;
        $read             = "{$this->outcomes}/read-{$mine}";
        $peerRead         = "{$this->outcomes}/read-{$peer}";

        $wait = static function () use ($read, $peerRead): void {
            touch($read);
            self::await($peerRead);
        };

        $this->app?->instance(LinkLimit::class, new class ($wait) implements LinkLimit {
            /** @var bool Whether the limit has waited for the peer. */
            private bool $waited = false;

            /**
             * Constructor.
             *
             * @param  \Closure(): void  $wait
             */
            public function __construct(

                /** Signals this racer has read, and waits for the peer to have read too. */
                private readonly \Closure $wait,
            ) {}

            /**
             * Wait, the first time, for both racers to have read, and allow one
             * link.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return int
             */
            #[\Override]
            public function maxLinks(IdentityReference $identity, SsoConnection $connection): int
            {
                unset($identity, $connection);

                if (!$this->waited) {
                    $this->waited = true;

                    ($this->wait)();
                }

                return 1;
            }
        });

        Event::listen(ResultUnlinked::class, function (ResultUnlinked $event) use ($identity, &$status, &$attempts): void {

            $database = DB::connection(StorageConnection::name());

            $database->statement(self::repeatableReadStatement($database->getDriverName()));

            $database->transaction(function () use ($event, $identity, &$status, &$attempts): void {
                $attempts++;
                $status = app(ProvisioningHelper::class)->link($event->grant, $event->result, $identity, Clients::browser())->status->value;
            }, 3);
        });

        $completion = $this->completion($state);

        return [
            'helper'     => $status,
            'attempts'   => $attempts,
            'completion' => $completion->status->value,
            'reason'     => $completion->reason?->value,
        ];
    }

    /**
     * In a forked process: open a transaction and read first when asked, signal
     * it has read, make the change and commit; roll back whatever went wrong,
     * and signal the change ended, whatever came of it.
     *
     * @param  bool  $inTransaction
     * @param  string  $read
     * @param  string  $changed
     * @param  \Closure(): string  $change
     * @return array<string, mixed>
     */
    private function changing(bool $inTransaction, string $read, string $changed, \Closure $change): array
    {
        $database = DB::connection(StorageConnection::name());

        try {
            if ($inTransaction) {
                $this->openAndRead($database);
            }

            touch($read);

            $status = $change();

            if ($inTransaction) {
                $database->commit();
            }

            return ['status' => $status];
        } finally {
            if ($database->transactionLevel() > 0) {
                $database->rollBack();
            }

            touch($changed);
        }
    }

    /**
     * In a forked process: open a transaction and read first when asked, signal
     * it is ready, wait for the result's offer, make the link and commit.
     *
     * @param  bool  $inTransaction
     * @param  string  $offered
     * @param  string  $ready
     * @return array<string, mixed>
     */
    private function explicitLink(bool $inTransaction, string $offered, string $ready): array
    {
        $database = DB::connection(StorageConnection::name());

        if ($inTransaction) {
            $this->openAndRead($database);
        }

        touch($ready);
        self::await($offered);

        $creation = app(LinkStore::class)->create(
            Connection::query()->whereKey($this->connection->id)->firstOrFail(),
            new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT),
            $this->other,
            LinkOrigin::LINK_PURPOSE,
            Clients::browser(),
        );

        if ($inTransaction) {
            $database->commit();
        }

        return ['status' => $creation->status->value];
    }

    /**
     * Set this session's transactions to `REPEATABLE READ`, open one, and read
     * the connection, its requests and its links, which on PostgreSQL pins the
     * snapshot.
     *
     * @param  \Illuminate\Database\Connection  $database
     * @return void
     */
    private function openAndRead(DatabaseConnection $database): void
    {
        $database->statement(self::repeatableReadStatement($database->getDriverName()));
        $database->beginTransaction();

        Connection::query()->whereKey($this->connection->id)->get();
        AuthorizationRequest::query()->where('connection_id', $this->connection->id)->get();
        Link::query()->where('connection_id', $this->connection->id)->get();
    }

    /**
     * Disable the connection, and answer what came of it.
     *
     * @return string
     */
    private function disabled(): string
    {
        return app(ConnectionLifecycle::class)->disable('tenant-1', $this->connection->id, Clients::browser())->status->value;
    }

    /**
     * Change the connection's issuer, which raises its trust version, and
     * answer what came of it.
     *
     * @return string
     */
    private function trustChanged(): string
    {
        return app(ConnectionService::class)->update('tenant-1', $this->connection->id, ['settings' => ['issuer' => self::NEW_ISSUER]], Clients::browser())->status->value;
    }

    /**
     * Start a flow, and answer its protocol state and how it started.
     *
     * @return array{0: string, 1: \SineMacula\Laravel\Sso\Flows\StartResult}
     */
    private function startedFlow(): array
    {
        $start = $this->start();

        return [$this->starting->lastStart()->state->reveal(), $start];
    }

    /**
     * Answer the flow with the state at its callback.
     *
     * @param  string  $state
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function completion(string $state): CompletionResult
    {
        return app(CompletionService::class)->complete(
            CompletionEndpoint::CALLBACK,
            $this->connection->id,
            new CompletionRequest('GET', 'state=' . rawurlencode($state), []),
            Clients::browser(),
        );
    }

    /**
     * Redeem the code a racer reported, with its flow's verifier, in this
     * process, once the race has ended.
     *
     * @param  array<string, mixed>  $outcome
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function redeemed(array $outcome, StartResult $start): RedemptionResult
    {
        $code     = is_string($outcome['code'] ?? null) ? $outcome['code'] : '';
        $verifier = (string) $start->verifier?->reveal();

        return DB::connection(StorageConnection::name())->transaction(
            fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $this->connection->id, $code, $verifier, Clients::browser()),
        );
    }

    /**
     * Fork a process per body, have each run on a connection of its own, and
     * collect what each reported, in order.
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

            $outcome = json_decode((string) @file_get_contents("{$this->outcomes}/{$process}"), true);

            $outcomes[] = is_array($outcome) ? $outcome : ['status' => 'unreadable'];
        }

        return $outcomes;
    }

    /**
     * In a forked process: open a connection of its own, run the body, report
     * what it answered, whether it failed to serialise, or the error it threw,
     * and end without running the parent's shutdown.
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
            $outcome = self::isSerializationFailure($e) ? ['status' => self::SERIALIZATION] : ['status' => 'error', 'reason' => $e::class . ': ' . $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/{$process}", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Run the closure, when there is one.
     *
     * @param  ?\Closure(): void  $closure
     * @return void
     */
    private static function runIfGiven(?\Closure $closure): void
    {
        if ($closure === null) {
            return;
        }

        $closure();
    }

    /**
     * Whether the racer failed to serialise, which is a safe end only inside a
     * transaction on PostgreSQL.
     *
     * @param  array<string, mixed>  $outcome
     * @param  bool  $inTransaction
     * @return bool
     */
    private static function serializes(array $outcome, bool $inTransaction): bool
    {
        if (($outcome['status'] ?? null) !== self::SERIALIZATION) {
            return false;
        }

        self::assertTrue($inTransaction && DB::connection()->getDriverName() === 'pgsql', 'Only a transaction on PostgreSQL may fail to serialise.');

        return true;
    }

    /**
     * What the racers reported, for a failure's message; the codes left out.
     *
     * @param  array<string, mixed>  ...$outcomes
     * @return string
     */
    private static function reported(array ...$outcomes): string
    {
        return (string) json_encode(array_map(static fn (array $outcome): array => array_diff_key($outcome, ['code' => true]), $outcomes));
    }

    /**
     * The statement that makes this session's transactions `REPEATABLE READ`.
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
     * Wait for the signal file, for at most `SIGNAL_SECONDS`, and fail loudly
     * when it never appears: the racer then reports an error, so a race whose
     * racers ran one after the other never passes as one that overlapped.
     *
     * @param  string  $signal
     * @return void
     *
     * @throws \RuntimeException
     */
    private static function await(string $signal): void
    {
        $deadline = microtime(true) + self::SIGNAL_SECONDS;

        while (!file_exists($signal)) {

            if (microtime(true) > $deadline) {
                throw new \RuntimeException(sprintf('The barrier timed out waiting for [%s].', basename($signal)));
            }

            usleep(1000);
            clearstatcache(true, $signal);
        }
    }

    /**
     * Whether the error, or one it was thrown for, is PostgreSQL's
     * serialisation failure (SQLSTATE `40001`), accepted only there.
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
}
