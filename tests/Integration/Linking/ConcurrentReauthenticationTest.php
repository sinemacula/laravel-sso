<?php

declare(strict_types = 1);

namespace Tests\Integration\Linking;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\ReauthenticationCompleted;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\Redemption\ReauthenticationBranch;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Races a `reauthenticate` redemption across processes, each with its own
 * database connection, on MySQL and PostgreSQL (SSO-5.10, SSO-9.5, SSO-9.9,
 * `docs/design/linking.md`), against what can change the session or the link
 * under it: the session's revocation, the link's removal, its suspension by a
 * widened scope, and a second redemption of the one code.
 *
 * The session is a row on the storage connection, in a table of this test's,
 * behind a contract written as an implementation must be: `lockedStanding()`
 * locks the row, and `renewAuthentication()` writes only an active one,
 * throwing otherwise, so a renewal of a revoked session fails the race loudly
 * instead of passing unseen. A revocation locks the row too, and records
 * whether it saw a renewal when it did.
 *
 * The order is fixed by signal files, never by time, and a barrier that times
 * out fails the racer loudly: each process opens its connection and, racing in
 * a transaction, begins one at `REPEATABLE READ` and reads the connection, the
 * links, the codes and the session; once both have signalled that, the first
 * does its work and signals before it commits; only then does the second start.
 * So in a transaction, the second's snapshot predates everything the first
 * wrote, and its locking reads either wait for the first to commit or find it
 * committed; on MySQL they must answer what is committed rather than the
 * snapshot, and on PostgreSQL a locking read of a row the first changed fails
 * to serialise (SQLSTATE `40001`, possibly wrapped in a `DeadlockException`),
 * which rolls it back whole and is accepted there alone. A redemption writes
 * neither the connection's row nor the link's, so what follows it fails on the
 * session's row or the code's; a removal or a suspension raises the
 * connection's links version, so a redemption following one fails on the
 * connection's row. Each race runs both ways round; those with no fixed order
 * run with both going at once, once both have read.
 *
 * A process reports how its work ended, then how many
 * `ReauthenticationCompleted` it reported once it committed. Skipped on SQLite,
 * whose in-memory database each process would have to itself, and where `pcntl`
 * is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReauthenticationBranch::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(LinkService::class)]
#[CoversClass(LinkStore::class)]
#[CoversClass(ScopeWidening::class)]
final class ConcurrentReauthenticationTest extends LinkingTestCase
{
    /** @var float Seconds a racer waits for the other's signal before it gives up. */
    private const float SIGNAL_SECONDS = 30.0;

    /** @var string What a racer reports when it failed to serialise, accepted on PostgreSQL alone. */
    private const string SERIALIZATION = 'serialization';

    /** @var string The session the flows are started on. */
    private const string SESSION = 'session-1';

    /** @var string The table the session contract keeps its row in. */
    private const string SESSIONS = 'reauthentication_race_sessions';

    /** @var string The authentication time the session holds until renewed. */
    private const string EARLIER = '2026-11-01T08:00:00.000000Z';

    /** @var string Directory the processes signal and report in. */
    private string $signals;

    /**
     * Bind a fresh caller, the session and revocation contracts over the table,
     * and a limiter that allows every attempt, whose counters a racer's
     * transaction would otherwise hold locked; and create the table and the
     * directory the processes report in.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(ReauthenticationSessions::class, $this->sessionContract());
        $this->app?->instance(SessionRevocation::class, $this->revocationContract());
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

        DB::connection(StorageConnection::name())->getSchemaBuilder()->create(self::SESSIONS, static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('identity_type');
            $table->string('identity_id');
            $table->string('application');
            $table->string('connection_id');
            $table->string('link_id');
            $table->boolean('active');
            $table->string('authenticated_at');
            $table->integer('renewals')->default(0);
            $table->boolean('saw_renewal')->nullable();
        });

        $this->signals = sys_get_temp_dir() . '/reauthentication-race-' . bin2hex(random_bytes(8));

        mkdir($this->signals);
    }

    /**
     * Remove this test's signals and outcomes, and drop the table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if (isset($this->signals) && is_dir($this->signals)) {

            foreach (glob($this->signals . '/*') ?: [] as $file) {
                @unlink($file);
            }

            @rmdir($this->signals);
        }

        DB::connection(StorageConnection::name())->getSchemaBuilder()->dropIfExists(self::SESSIONS);

        parent::tearDown();
    }

    /**
     * Each racer plainly, and each inside its own already-open transaction that
     * read first.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function isolations(): iterable
    {
        yield 'plainly' => [false];
        yield 'inside a transaction that read first' => [true];
    }

    /**
     * A redemption then a revocation: the revocation waits for the renewal,
     * sees it, and revokes.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testARedemptionThenARevocation(bool $inTransaction): void
    {
        $this->sessionOn($this->hold());

        $flow     = $this->flow();
        $outcomes = $this->race($this->redeemer($flow), $this->revoker(), $inTransaction);

        if ($this->failsToSerialize($inTransaction)) {

            self::assertSame(['redeemed|1', self::SERIALIZATION], $outcomes);
            self::assertSame([1, true, false], $this->sessionState());

            return;
        }

        self::assertSame(['redeemed|1', 'revoked|0'], $outcomes);
        self::assertSame([1, false, true], $this->sessionState());
    }

    /**
     * A revocation then a redemption: the redemption sees the session revoked,
     * `session_ineligible`, with the code spent, and renews nothing.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testARevocationThenARedemption(bool $inTransaction): void
    {
        $this->sessionOn($this->hold());

        $flow     = $this->flow();
        $outcomes = $this->race($this->revoker(), $this->redeemer($flow), $inTransaction);

        self::assertSame([0, false, false], $this->sessionState());

        if ($this->failsToSerialize($inTransaction)) {

            self::assertSame(['revoked|0', self::SERIALIZATION], $outcomes);
            self::assertNull($this->storedCode($flow[0])->redeemed_at);

            return;
        }

        self::assertSame(['revoked|0', 'refused:session_ineligible|0'], $outcomes);
        self::assertNotNull($this->storedCode($flow[0])->redeemed_at);
    }

    /**
     * A redemption and a revocation going at once, once both have read:
     * whichever takes the row first, a revoked session is never renewed. The
     * contract throws if it is asked to, and an error fails the race.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testARedemptionAndARevocationAtOnce(bool $inTransaction): void
    {
        $this->sessionOn($this->hold());

        $flow     = $this->flow();
        $outcomes = $this->race($this->redeemer($flow), $this->revoker(), $inTransaction, false);

        $allowed = $this->failsToSerialize($inTransaction)
            ? [['redeemed|1', self::SERIALIZATION], [self::SERIALIZATION, 'revoked|0']]
            : [['redeemed|1', 'revoked|0'], ['refused:session_ineligible|0', 'revoked|0']];

        self::assertContains($outcomes, $allowed);

        [$renewals, $active, $sawRenewal] = $this->sessionState();

        self::assertSame($outcomes[0] === 'redeemed|1' ? 1 : 0, $renewals);
        self::assertSame($outcomes[1] === self::SERIALIZATION, $active);
        self::assertSame($outcomes[1] === 'revoked|0' && $renewals === 1, $sawRenewal);
    }

    /**
     * A redemption then the link's removal: the session is renewed through the
     * link while it stands, and the removal then sees that and revokes it.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testARedemptionThenARemovalOfItsLink(bool $inTransaction): void
    {
        $link = $this->hold();

        $this->sessionOn($link);

        $flow     = $this->flow();
        $outcomes = $this->race($this->redeemer($flow), $this->remover($link->id), $inTransaction);

        if ($this->failsToSerialize($inTransaction)) {

            self::assertSame(['redeemed|1', self::SERIALIZATION], $outcomes);
            self::assertSame([1, true, false], $this->sessionState());
            self::assertSame(1, Link::query()->count());

            return;
        }

        self::assertSame(['redeemed|1', 'removed|0'], $outcomes);
        self::assertSame([1, false, true], $this->sessionState());
        self::assertSame(0, Link::query()->count());
    }

    /**
     * The link's removal then a redemption: the redemption finds the link it
     * observed gone, `identity_mismatch`, and renews nothing.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testARemovalOfItsLinkThenARedemption(bool $inTransaction): void
    {
        $link = $this->hold();

        $this->sessionOn($link);

        $flow     = $this->flow();
        $outcomes = $this->race($this->remover($link->id), $this->redeemer($flow), $inTransaction);

        self::assertSame(0, Link::query()->count());
        self::assertSame([0, false, false], $this->sessionState());

        if ($this->failsToSerialize($inTransaction)) {

            self::assertSame(['removed|0', self::SERIALIZATION], $outcomes);
            self::assertNull($this->storedCode($flow[0])->redeemed_at);

            return;
        }

        self::assertSame(['removed|0', 'refused:identity_mismatch|0'], $outcomes);
        self::assertNotNull($this->storedCode($flow[0])->redeemed_at);
    }

    /**
     * A redemption then a principal change suspending the link: the session is
     * renewed while the link stands, and the change then suspends the link and
     * revokes the session, seeing the renewal.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testARedemptionThenASuspensionOfItsLink(bool $inTransaction): void
    {
        $this->sessionOn($this->hold(LinkOrigin::VERIFIED_DOMAIN));

        $flow     = $this->flow();
        $outcomes = $this->race($this->redeemer($flow), $this->widener(), $inTransaction);

        if ($this->failsToSerialize($inTransaction)) {

            self::assertSame(['redeemed|1', self::SERIALIZATION], $outcomes);
            self::assertSame([1, true, false], $this->sessionState());
            self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);

            return;
        }

        self::assertSame(['redeemed|1', 'widened:1|0'], $outcomes);
        self::assertSame([1, false, true], $this->sessionState());
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
    }

    /**
     * A principal change suspending the link then a redemption: the redemption
     * finds it suspended, `link_suspended`, and renews nothing.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testASuspensionOfItsLinkThenARedemption(bool $inTransaction): void
    {
        $this->sessionOn($this->hold(LinkOrigin::VERIFIED_DOMAIN));

        $flow     = $this->flow();
        $outcomes = $this->race($this->widener(), $this->redeemer($flow), $inTransaction);

        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
        self::assertSame([0, false, false], $this->sessionState());

        if ($this->failsToSerialize($inTransaction)) {

            self::assertSame(['widened:1|0', self::SERIALIZATION], $outcomes);
            self::assertNull($this->storedCode($flow[0])->redeemed_at);

            return;
        }

        self::assertSame(['widened:1|0', 'refused:link_suspended|0'], $outcomes);
        self::assertNotNull($this->storedCode($flow[0])->redeemed_at);
    }

    /**
     * Two redemptions of one code in turn: one renewal and one completion; the
     * other is `replayed`.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testTwoRedemptionsOfOneCodeInTurn(bool $inTransaction): void
    {
        $this->sessionOn($this->hold());

        $flow     = $this->flow();
        $outcomes = $this->race($this->redeemer($flow), $this->redeemer($flow), $inTransaction);

        self::assertSame(
            $this->failsToSerialize($inTransaction) ? ['redeemed|1', self::SERIALIZATION] : ['redeemed|1', 'refused:replayed|0'],
            $outcomes,
        );
        self::assertSame([1, true, false], $this->sessionState());
    }

    /**
     * Two redemptions of one code at once, once both have read: whichever wins,
     * one renewal and one completion.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testTwoRedemptionsOfOneCodeAtOnce(bool $inTransaction): void
    {
        $this->sessionOn($this->hold());

        $flow     = $this->flow();
        $outcomes = $this->race($this->redeemer($flow), $this->redeemer($flow), $inTransaction, false);

        sort($outcomes);

        self::assertSame(
            $this->failsToSerialize($inTransaction) ? ['redeemed|1', self::SERIALIZATION] : ['redeemed|1', 'refused:replayed|0'],
            $outcomes,
        );
        self::assertSame([1, true, false], $this->sessionState());
    }

    /**
     * Make a link of the subject for the person, through the store.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function hold(LinkOrigin $origin = LinkOrigin::PROVISIONING): Link
    {
        $creation = app(LinkStore::class)->create(
            $this->connection,
            new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT),
            $this->person,
            $origin,
            Clients::browser(),
        );

        self::assertTrue($creation->isCreated());

        return Link::query()->whereKey($creation->link?->id)->sole();
    }

    /**
     * Insert the person's active session, established through the link.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @return void
     */
    private function sessionOn(Link $link): void
    {
        $this->sessions()->insert([
            'id'               => self::SESSION,
            'identity_type'    => $this->person->type,
            'identity_id'      => $this->person->id,
            'application'      => 'web',
            'connection_id'    => $this->connection->id,
            'link_id'          => $link->id,
            'active'           => true,
            'authenticated_at' => self::EARLIER,
        ]);
    }

    /**
     * Start and complete a `reauthenticate`, in this process, before any fork.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: string, 2: string}
     */
    private function flow(): array
    {
        $start      = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());

        return [$start, (string) $completion->handoff?->code->reveal(), (string) $start->verifier?->reveal()];
    }

    /**
     * What a process redeeming the code does: admit it inside a transaction, a
     * savepoint when it has one open already, and say how it ended.
     *
     * @param  array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: string, 2: string}  $flow
     * @return \Closure(): string
     */
    private function redeemer(array $flow): \Closure
    {
        return fn (): string => self::outcomeOf(DB::connection(StorageConnection::name())->transaction(
            fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::REAUTHENTICATE, 'web', $this->connection->id, $flow[1], $flow[2], Clients::browser()),
        ));
    }

    /**
     * What a process revoking the session does: the application's revocation,
     * in a transaction of its own.
     *
     * @return \Closure(): string
     */
    private function revoker(): \Closure
    {
        return function (): string {

            DB::connection(StorageConnection::name())->transaction(fn () => $this->revokeTheSession());

            return 'revoked';
        };
    }

    /**
     * What a process removing the link does, which revokes through the contract
     * in its transaction.
     *
     * @param  string  $linkId
     * @return \Closure(): string
     */
    private function remover(string $linkId): \Closure
    {
        return function () use ($linkId): string {

            $removal = app(LinkService::class)->remove($this->person, $linkId, Clients::browser());

            return $removal->isRemoved() ? 'removed' : 'refused:' . $removal->reason?->value;
        };
    }

    /**
     * What a process widening the person's scope does: report a principal of
     * another tenant in a transaction of its own, which suspends the link and
     * revokes through the contract, and say how many links it suspended.
     *
     * @return \Closure(): string
     */
    private function widener(): \Closure
    {
        return fn (): string => 'widened:' . DB::connection(StorageConnection::name())->transaction(
            fn (): int => app(ScopeWidening::class)->widened($this->person, 'tenant-2', Clients::browser()),
        );
    }

    /**
     * Lock the session's row, note whether a renewal had been made by then, and
     * revoke it.
     *
     * @return void
     */
    private function revokeTheSession(): void
    {
        $row = $this->sessions()->where('id', self::SESSION)->useWritePdo()->lockForUpdate()->sole();

        $this->sessions()->where('id', self::SESSION)->update(['active' => false, 'saw_renewal' => (int) ($row->renewals ?? 0) > 0]);
    }

    /**
     * How a redemption ended.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $answer
     * @return string
     */
    private static function outcomeOf(RedemptionResult $answer): string
    {
        return $answer->isRedeemed() ? 'redeemed' : 'refused:' . $answer->reason?->value;
    }

    /**
     * Whether, racing in a transaction, the second racer fails to serialise.
     *
     * @param  bool  $inTransaction
     * @return bool
     */
    private function failsToSerialize(bool $inTransaction): bool
    {
        return $inTransaction && DB::connection(StorageConnection::name())->getDriverName() === 'pgsql';
    }

    /**
     * The stored code of the flow.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return \SineMacula\Laravel\Sso\Models\HandoffCode
     */
    private function storedCode(StartResult $start): StoredCode
    {
        return StoredCode::query()->where('request_reference', $start->reference?->value)->sole();
    }

    /**
     * The session table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function sessions(): Builder
    {
        return DB::connection(StorageConnection::name())->table(self::SESSIONS);
    }

    /**
     * How many renewals the session had, whether it is active, and whether a
     * revocation saw a renewal.
     *
     * @return array{0: int, 1: bool, 2: bool}
     */
    private function sessionState(): array
    {
        $row = $this->sessions()->where('id', self::SESSION)->sole();

        return [(int) ($row->renewals ?? 0), (bool) ($row->active ?? false), (bool) ($row->saw_renewal ?? false)];
    }

    /**
     * The session contract over the table: `lockedStanding()` locks the row and
     * compares all five values, and `renewAuthentication()` writes only an
     * active row, throwing otherwise.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions
     */
    private function sessionContract(): ReauthenticationSessions
    {
        return new readonly class (fn (): Builder => $this->sessions()) implements ReauthenticationSessions {
            /**
             * Constructor.
             *
             * @param  \Closure(): \Illuminate\Database\Query\Builder  $rows
             */
            public function __construct(

                /** The table's rows. */
                private \Closure $rows,
            ) {}

            /**
             * Whether the identity holds the active session through the
             * connection.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            #[\Override]
            public function standing(IdentityReference $identity, string $sessionId, SsoConnection $connection): SessionStanding
            {
                $row = ($this->rows)()->where('id', $sessionId)->useWritePdo()->first();

                return self::answer($row, ['identity_type' => $identity->type, 'identity_id' => $identity->id, 'connection_id' => $connection->getConnectionId()]);
            }

            /**
             * Lock the session's row, and whether all five match.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  string  $application
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  string  $linkId
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            #[\Override]
            public function lockedStanding(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection, string $linkId): SessionStanding
            {
                $row = ($this->rows)()->where('id', $sessionId)->useWritePdo()->lockForUpdate()->first();

                return self::answer($row, [
                    'identity_type' => $identity->type,
                    'identity_id'   => $identity->id,
                    'application'   => $application,
                    'connection_id' => $connection->getConnectionId(),
                    'link_id'       => $linkId,
                ]);
            }

            /**
             * Renew the active row, or fail the race.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  \Carbon\CarbonImmutable  $authenticatedAt
             * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
             * @return void
             *
             * @throws \LogicException
             */
            #[\Override]
            public function renewAuthentication(IdentityReference $identity, string $sessionId, CarbonImmutable $authenticatedAt, ?AcceptedEvidence $evidence): void
            {
                unset($identity, $evidence);

                $at      = $authenticatedAt->utc()->format('Y-m-d\TH:i:s.u\Z');
                $renewed = ($this->rows)()->where('id', $sessionId)->where('active', true)->increment('renewals', 1, ['authenticated_at' => $at]);

                if ($renewed !== 1) {
                    throw new \LogicException('A revoked session was renewed.');
                }
            }

            /**
             * Signed in when the row is active with each value given.
             *
             * @param  ?object  $row
             * @param  array<string, string>  $values
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            private static function answer(?object $row, array $values): SessionStanding
            {
                if ($row === null || !(bool) ($row->active ?? false)) {
                    return SessionStanding::NOT_SIGNED_IN;
                }

                $read    = (array) $row;
                $differs = array_filter($values, static fn (mixed $value, string $column): bool => ($read[$column] ?? null) !== $value, ARRAY_FILTER_USE_BOTH);

                return $differs === [] ? SessionStanding::SIGNED_IN : SessionStanding::NOT_SIGNED_IN;
            }
        };
    }

    /**
     * The revocation contract over the table, which revokes the one session
     * inside the change's transaction.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SessionRevocation
     */
    private function revocationContract(): SessionRevocation
    {
        return new readonly class (fn () => $this->revokeTheSession()) implements SessionRevocation {
            /**
             * Constructor.
             *
             * @param  \Closure(): void  $revoke
             */
            public function __construct(

                /** Revokes the session. */
                private \Closure $revoke,
            ) {}

            /**
             * Revoke the session, under the row's lock.
             *
             * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
             * @return void
             */
            #[\Override]
            public function revoke(RevocationScope $scope): void
            {
                unset($scope);

                ($this->revoke)();
            }
        };
    }

    /**
     * Fork a process for each racer on a connection of its own, plain or inside
     * a transaction of its own, and collect what each reported, in the racers'
     * order. In turn, the first signals once it has done its work and the
     * second starts only then; otherwise both start once both have read.
     *
     * @param  \Closure(): string  $first
     * @param  \Closure(): string  $second
     * @param  bool  $inTransaction
     * @param  bool  $inTurn
     * @return list<string>
     */
    private function race(\Closure $first, \Closure $second, bool $inTransaction, bool $inTurn = true): array
    {
        if (DB::connection(StorageConnection::name())->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        DB::disconnect();
        DB::disconnect(StorageConnection::name());

        $pids = [];

        foreach ([$first, $second] as $process => $work) {

            $pid = pcntl_fork();

            if ($pid === 0) {
                $this->runInChild($process, $work, $inTransaction, $inTurn);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        return [(string) file_get_contents("{$this->signals}/outcome-0"), (string) file_get_contents("{$this->signals}/outcome-1")];
    }

    /**
     * In a forked process: open a connection of its own and, in a transaction,
     * begin one at `REPEATABLE READ` and read; signal that; wait for the
     * other's signal; wait for the first's work, when the second in turn; do
     * its work, signalling before it commits; report how it ended and what it
     * reported; and end without running the parent's shutdown.
     *
     * @param  int  $process
     * @param  \Closure(): string  $work
     * @param  bool  $inTransaction
     * @param  bool  $inTurn
     * @return never
     */
    private function runInChild(int $process, \Closure $work, bool $inTransaction, bool $inTurn): never
    {
        try {
            DB::purge();
            DB::purge(StorageConnection::name());
            DB::connection()->getPdo();

            $this->startRecordingEvents();

            $database = DB::connection(StorageConnection::name());

            if ($inTransaction) {
                $database->statement(self::repeatableReadStatement($database->getDriverName()));
                $database->beginTransaction();
                Connection::query()->whereKey($this->connection->id)->get();
                Link::query()->get();
                StoredCode::query()->get();
                $database->table(self::SESSIONS)->get();
            }

            touch("{$this->signals}/read-{$process}");

            self::await("{$this->signals}/read-" . (1 - $process));

            if ($inTurn && $process === 1) {
                self::await("{$this->signals}/worked");
            }

            try {
                $outcome = $work();
            } finally {
                touch("{$this->signals}/worked");
            }

            if ($inTransaction) {
                $database->commit();
            }

            $outcome .= '|' . $this->completionsReported();
        } catch (\Throwable $e) {
            $outcome = self::isSerializationFailure($e) ? self::SERIALIZATION : 'error: ' . $e::class . ': ' . $e->getMessage();
        }

        file_put_contents("{$this->signals}/outcome-{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * How many `ReauthenticationCompleted` this process reported.
     *
     * @return int
     */
    private function completionsReported(): int
    {
        return count(array_filter($this->recordedEvents(), static fn (object $event): bool => $event instanceof ReauthenticationCompleted));
    }

    /**
     * The statement that makes this session's transactions `REPEATABLE READ`,
     * which on PostgreSQL pins the snapshot at the first read.
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
     * serialisation failure (SQLSTATE `40001`), accepted only there: a
     * `DeadlockException` wraps it, so every previous error is walked.
     *
     * @param  \Throwable  $exception
     * @return bool
     */
    private static function isSerializationFailure(\Throwable $exception): bool
    {
        for ($error = $exception; $error !== null; $error = $error->getPrevious()) {
            if ((string) $error->getCode() === '40001') {
                return DB::connection(StorageConnection::name())->getDriverName() === 'pgsql';
            }
        }

        return false;
    }
}
