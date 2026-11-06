<?php

declare(strict_types = 1);

namespace Tests\Integration\Combined;

use Carbon\CarbonImmutable;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\LinkActivated;
use SineMacula\Laravel\Sso\Events\LinkConfirmed;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\ReauthenticationCompleted;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\Redemption\LinkBranch;
use SineMacula\Laravel\Sso\Handoffs\Redemption\ReauthenticationBranch;
use SineMacula\Laravel\Sso\Handoffs\Redemption\SignInBranch;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\ReservationActivation;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RaceFlows;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * What a failure in TR, the redemption's transaction, rolls back, on every
 * database the suite runs on (SSO-9.9, SSO-10.5, SSO-11.4, decision D5,
 * `docs/design/transaction-ownership.md`). Consumption, activation, the
 * application's session and its evidence commit or roll back together, in the
 * caller's transaction on the storage connection, for `sign_in`, `link` and
 * `reauthenticate`.
 *
 * Each test names TR as what it rolls back, and compares every row stored
 * before and after, with a failure injected before and after each of its
 * mutations and at its commit: handoff consumption failing, what stands for
 * link activation in each purpose failing (activating a reservation, creating
 * or confirming a link, renewing a session), and the application's own writes
 * failing. No event of TR escapes, and the redemption then goes through whole,
 * since the code was never spent. What is committed outside TR stays, and is
 * asserted to: an attempt counted on the counters' own connection, and one a
 * standalone `link` counted before its transaction opened.
 *
 * Cases `RedemptionTransactionTest` pins are not repeated: a rollback by the
 * caller with nothing failing, and a linker that throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(SignInBranch::class)]
#[CoversClass(LinkBranch::class)]
#[CoversClass(ReauthenticationBranch::class)]
#[CoversClass(ReservationActivation::class)]
final class RedemptionRollbackTest extends LinkingTestCase
{
    use RaceFlows;

    /** @var string The table the application keeps its sessions in. */
    private const string SESSIONS = 'combined_rollback_sessions';

    /** @var string The table the application keeps what it accepted in. */
    private const string EVIDENCE = 'combined_rollback_evidence';

    /** @var string A `sign_in` code bound to a reservation. */
    private const string RESERVED = 'a reserved sign_in';

    /** @var string A `sign_in` code that resolved to a link. */
    private const string LINKED = 'a linked sign_in';

    /** @var string A `link` code of a subject nobody holds. */
    private const string CREATING = 'a link creating';

    /** @var string A `link` code of a subject the identity holds by a verified domain. */
    private const string CONFIRMING = 'a link confirming';

    /** @var string A `reauthenticate` code. */
    private const string REAUTHENTICATING = 'a reauthenticate';

    /** @var string The session the flows are started on. */
    private const string SESSION = 'session-1';

    /** @var string The authentication time the session holds until renewed. */
    private const string EARLIER = '2026-11-01T08:00:00Z';

    /** @var string The rate limits' migration. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var string The separate connection the counters are moved to. */
    private const string COUNTERS = 'counters';

    /** @var ?\Throwable What the session contract throws once it has written. */
    private ?\Throwable $renewalFailure = null;

    /**
     * Bind a fresh caller, an eligibility that lets every identity link, and
     * the session contract over the application's table, and create its tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
        $this->app?->instance(ReauthenticationSessions::class, $this->sessionContract());

        $schema = self::storageDatabase()->getSchemaBuilder();

        $schema->create(self::SESSIONS, static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('identity_id');
            $table->string('link_id')->nullable();
            $table->string('authenticated_at');
        });

        $schema->create(self::EVIDENCE, static function (Blueprint $table): void {
            $table->id();
            $table->string('kind');
        });
    }

    /**
     * Drop the application's tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $schema = self::storageDatabase()->getSchemaBuilder();

        $schema->dropIfExists(self::EVIDENCE);
        $schema->dropIfExists(self::SESSIONS);

        parent::tearDown();
    }

    /**
     * Rows of `[the flow, the verb, the table, the occurrence]`, the verb
     * `null` for the commit: TR failed before and after each mutation of each
     * purpose.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: ?string, 3: int}>
     */
    public static function provideFailures(): iterable
    {
        yield self::RESERVED . ', at the identity guard' => [self::RESERVED, 'insert', 'identity_guards.table', 1];
        yield self::RESERVED . ', at the single-use record' => [self::RESERVED, 'insert', 'single_use.table', 1];
        yield self::RESERVED . ', at the consumption' => [self::RESERVED, 'update', 'handoff_codes.table', 1];
        yield self::RESERVED . ', at the activation' => [self::RESERVED, 'update', 'links.table', 1];
        yield self::RESERVED . ', at its links version' => [self::RESERVED, 'update', 'connections.table', 1];
        yield self::RESERVED . ', at the guard\'s stamp' => [self::RESERVED, 'update', 'identity_guards.table', 1];
        yield self::RESERVED . ', at the acknowledgement' => [self::RESERVED, 'update', 'connections.table', 2];
        yield self::RESERVED . ', at the application\'s session' => [self::RESERVED, 'insert', self::SESSIONS, 1];
        yield self::RESERVED . ', at the application\'s evidence' => [self::RESERVED, 'insert', self::EVIDENCE, 1];
        yield self::RESERVED . ', at its commit' => [self::RESERVED, null, null, 1];

        yield self::LINKED . ', at the single-use record' => [self::LINKED, 'insert', 'single_use.table', 1];
        yield self::LINKED . ', at the consumption' => [self::LINKED, 'update', 'handoff_codes.table', 1];
        yield self::LINKED . ', at the acknowledgement' => [self::LINKED, 'update', 'connections.table', 1];
        yield self::LINKED . ', at the application\'s session' => [self::LINKED, 'insert', self::SESSIONS, 1];
        yield self::LINKED . ', at the application\'s evidence' => [self::LINKED, 'insert', self::EVIDENCE, 1];
        yield self::LINKED . ', at its commit' => [self::LINKED, null, null, 1];

        yield self::CREATING . ', at the identity guard' => [self::CREATING, 'insert', 'identity_guards.table', 1];
        yield self::CREATING . ', at the single-use record' => [self::CREATING, 'insert', 'single_use.table', 1];
        yield self::CREATING . ', at the consumption' => [self::CREATING, 'update', 'handoff_codes.table', 1];
        yield self::CREATING . ', at the link' => [self::CREATING, 'insert', 'links.table', 1];
        yield self::CREATING . ', at its links version' => [self::CREATING, 'update', 'connections.table', 1];
        yield self::CREATING . ', at the application\'s write' => [self::CREATING, 'insert', self::EVIDENCE, 1];
        yield self::CREATING . ', at its commit' => [self::CREATING, null, null, 1];

        yield self::CONFIRMING . ', at the consumption' => [self::CONFIRMING, 'update', 'handoff_codes.table', 1];
        yield self::CONFIRMING . ', at the confirmation' => [self::CONFIRMING, 'update', 'links.table', 1];
        yield self::CONFIRMING . ', at its links version' => [self::CONFIRMING, 'update', 'connections.table', 1];
        yield self::CONFIRMING . ', at its commit' => [self::CONFIRMING, null, null, 1];

        yield self::REAUTHENTICATING . ', at the single-use record' => [self::REAUTHENTICATING, 'insert', 'single_use.table', 1];
        yield self::REAUTHENTICATING . ', at the consumption' => [self::REAUTHENTICATING, 'update', 'handoff_codes.table', 1];
        yield self::REAUTHENTICATING . ', at the renewal' => [self::REAUTHENTICATING, 'update', self::SESSIONS, 1];
        yield self::REAUTHENTICATING . ', at the application\'s evidence' => [self::REAUTHENTICATING, 'insert', self::EVIDENCE, 1];
        yield self::REAUTHENTICATING . ', at its commit' => [self::REAUTHENTICATING, null, null, 1];
    }

    /**
     * Rolls back TR. Whichever statement fails, every row stands as it did, the
     * code unspent, no link activated, created, confirmed or renewed through,
     * no session or evidence kept and no event reported; and the redemption
     * then goes through whole, reporting once.
     *
     * @param  string  $flow
     * @param  ?string  $verb
     * @param  ?string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideFailures')]
    public function testAFailureRollsTheRedemptionBackWhole(string $flow, ?string $verb, ?string $table, int $occurrence): void
    {
        $redeeming = $this->flowOf($flow);
        $before    = $this->stored();

        $this->startRecordingEvents();
        $this->armFailure($verb, $table, $occurrence);

        self::assertInjectedFailure(fn (): mixed => $this->redeemed($redeeming));

        self::assertSame(1, $this->databaseFailuresFired());
        self::assertSame(0, self::storageDatabase()->transactionLevel());
        self::assertSame($before, $this->stored());
        $this->assertNoEvents();

        $answer = $this->redeemed($redeeming);

        self::assertTrue($answer->isRedeemed());
        self::assertNotNull(HandoffCode::query()->sole()->redeemed_at);
        $this->assertEventSequence(self::eventsOf($flow));
    }

    /**
     * Rolls back TR: a session contract's write that fails inside the package's
     * transaction takes with it the application's write made before the
     * redemption, the consumption, and the renewal it made itself.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedAdapterWriteInsideThePackagesTransactionRollsEverythingBack(): void
    {
        $redeeming = $this->flowOf(self::REAUTHENTICATING);
        $before    = $this->stored();
        $failure   = new \RuntimeException('The session could not be renewed.');

        $this->renewalFailure = $failure;

        $this->startRecordingEvents();

        try {
            self::storageDatabase()->transaction(function () use ($redeeming): void {

                self::storageDatabase()->table(self::EVIDENCE)->insert(['kind' => 'before the redemption']);

                $this->admitted($redeeming);
            });

            self::fail('The redemption went on.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame($before, $this->stored());
        $this->assertNoEvents();

        $this->renewalFailure = null;

        self::assertTrue($this->redeemed($redeeming)->isRedeemed());
    }

    /**
     * Rolls back TR: a contract that throws once the reservation has been
     * activated leaves it reserved, with the guard unstamped and nothing
     * reported.
     *
     * @return void
     */
    public function testAContractFailingAfterTheActivationRollsItBack(): void
    {
        $redeeming = $this->flowOf(self::RESERVED);
        $row       = Link::query()->sole();
        $before    = $this->stored();
        $failure   = new \RuntimeException('The evidence could not be judged.');

        $this->app?->instance(EvidencePolicy::class, new readonly class ($failure) implements EvidencePolicy {
            /**
             * Constructor.
             *
             * @param  \RuntimeException  $failure
             */
            public function __construct(

                /** What it throws. */
                private \RuntimeException $failure,
            ) {}

            /**
             * Fail.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \Carbon\CarbonImmutable  $now
             * @return ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function evaluate(VerifiedResult $result, SsoConnection $connection, CarbonImmutable $now): ?AcceptedEvidence
            {
                unset($result, $connection, $now);

                throw $this->failure;
            }
        });

        $this->startRecordingEvents();

        try {
            $this->redeemed($redeeming);

            self::fail('The redemption went on.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame($before, $this->stored());
        self::assertSame(LinkState::RESERVED, Link::query()->whereKey($row->id)->sole()->state);
        $this->assertNoEvents();
    }

    /**
     * Rows of `[the verb, the table's key]`, the verb `null` for the commit: TR
     * failed committing a refusal.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideRefusalFailures(): iterable
    {
        yield 'at the reservation\'s deletion' => ['delete', 'links.table'];
        yield 'at its links version' => ['update', 'connections.table'];
        yield 'at its commit' => [null, null];
    }

    /**
     * Rolls back TR, one that refused: a refusal commits its consumption and
     * deletes the reservation, so one that fails leaves the reservation
     * standing, the code unspent and no `FlowFailed` reported, and the right
     * verifier then redeems it.
     *
     * @param  ?string  $verb
     * @param  ?string  $table
     * @return void
     */
    #[DataProvider('provideRefusalFailures')]
    public function testARefusalThatFailsRollsBackWhole(?string $verb, ?string $table): void
    {
        $redeeming = $this->flowOf(self::RESERVED);
        $before    = $this->stored();
        $wrong     = [$redeeming[0], $redeeming[1], 'another-clients-verifier-of-43-characters-0', $redeeming[3]];

        $this->startRecordingEvents();
        $this->armFailure($verb, $table, 1);

        self::assertInjectedFailure(fn (): mixed => self::storageDatabase()->transaction(fn (): RedemptionResult => $this->admitted($wrong)));

        self::assertSame($before, $this->stored());
        $this->assertNoEvents();
        self::assertTrue($this->redeemed($redeeming)->isRedeemed());
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
    }

    /**
     * Rows of `[the verb, the table's key]`, the verb `null` for the commit:
     * the standalone `link` failed.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideStandaloneFailures(): iterable
    {
        yield 'at the consumption' => ['update', 'handoff_codes.table'];
        yield 'at the link' => ['insert', 'links.table'];
        yield 'at its commit' => [null, null];
    }

    /**
     * Rolls back TR, a standalone `link`'s, which is the package's own
     * transaction. The attempt it counted before that opened is committed by
     * then, and stays.
     *
     * @param  ?string  $verb
     * @param  ?string  $table
     * @return void
     */
    #[DataProvider('provideStandaloneFailures')]
    public function testAStandaloneLinkRollsBackItsOwnTransactionAlone(?string $verb, ?string $table): void
    {
        $redeeming = $this->flowOf(self::CREATING);
        $before    = $this->stored(false);
        $attempts  = $this->attempts(null);

        $this->startRecordingEvents();
        $this->armFailure($verb, $table, 1);

        self::assertInjectedFailure(fn (): mixed => app(HandoffRedemption::class)->redeem(...$this->redemptionArguments($redeeming)));

        self::assertSame($before, $this->stored(false));
        self::assertSame($attempts + 1, $this->attempts(null));
        $this->assertNoEvents();

        $answer = app(HandoffRedemption::class)->redeem(...$this->redemptionArguments($redeeming));

        self::assertTrue($answer->isRedeemed());
        self::assertFalse($answer->isAdmitted());
        $this->assertEventSequence(self::eventsOf(self::CREATING));
    }

    /**
     * Rolls back TR, with the counters on a connection of their own: the
     * attempt the redemption counted is outside it, so it stays though
     * everything else goes.
     *
     * @return void
     */
    public function testACountOnItsOwnConnectionSurvivesTheRollback(): void
    {
        $redeeming = $this->flowOf(self::RESERVED);

        $this->useCountersConnection();

        $before   = $this->stored(false);
        $attempts = $this->attempts(self::COUNTERS);

        $this->startRecordingEvents();
        $this->failCommit();

        self::assertInjectedFailure(fn (): mixed => $this->redeemed($redeeming));

        self::assertSame($before, $this->stored(false));
        self::assertSame($attempts + 1, $this->attempts(self::COUNTERS));
        self::assertNull(HandoffCode::query()->sole()->redeemed_at);
        $this->assertNoEvents();
    }

    /**
     * Add the connection the counters are moved to: the storage connection's
     * configuration under another name.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('database.connections.' . self::COUNTERS, config('database.connections.testing'));
    }

    /**
     * Move the counters to their own connection, its table made where it is a
     * database of its own.
     *
     * @return void
     */
    private function useCountersConnection(): void
    {
        config()->set('sso.rate_limits.connection', self::COUNTERS);

        if (Schema::connection(self::COUNTERS)->hasTable(StorageConnection::table('rate_limits.table'))) {
            return;
        }

        /** @var \Illuminate\Database\Migrations\Migration $migration */
        $migration = require dirname(__DIR__, 3) . self::RATE_LIMITS_MIGRATION;

        self::assertInstanceOf(Migration::class, $migration);

        $migration->up(); // @phpstan-ignore method.notFound
    }

    /**
     * Every attempt counted on the connection, the storage connection's when
     * none is named.
     *
     * @param  ?string  $connection
     * @return int
     */
    private function attempts(?string $connection): int
    {
        return (int) DB::connection($connection ?? StorageConnection::name())->table(StorageConnection::table('rate_limits.table'))->sum('hits');
    }

    /**
     * Every row stored, of the package's tables and the application's; the
     * counters, which may stand apart from the transaction, only when asked
     * for.
     *
     * @param  bool  $withCounters
     * @return array<string, list<string>>
     */
    private function stored(bool $withCounters = true): array
    {
        $rows = self::storedRows([self::SESSIONS, self::EVIDENCE]);

        if (!$withCounters) {
            unset($rows[StorageConnection::table('rate_limits.table')]);
        }

        return $rows;
    }

    /**
     * Make the flow's code ready in this process, and answer what redeems it:
     * the purpose, the code, the verifier and the caller.
     *
     * @param  string  $flow
     * @return array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: string, 2: string, 3: ?\SineMacula\Laravel\Sso\Identities\IdentityReference}
     *
     * @throws \LogicException
     */
    private function flowOf(string $flow): array
    {
        return match ($flow) {
            self::RESERVED         => $this->completed(Purpose::SIGN_IN),
            self::LINKED           => $this->holding(LinkOrigin::PROVISIONING, Purpose::SIGN_IN),
            self::CREATING         => $this->completed(Purpose::LINK, $this->person, null, $this->person),
            self::CONFIRMING       => $this->holding(LinkOrigin::VERIFIED_DOMAIN, Purpose::LINK, $this->person),
            self::REAUTHENTICATING => $this->reauthenticating(),
            default                => throw new \LogicException(sprintf('No flow is named [%s].', $flow)),
        };
    }

    /**
     * Link the subject to the person, then complete the flow.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: string, 2: string, 3: ?\SineMacula\Laravel\Sso\Identities\IdentityReference}
     */
    private function holding(LinkOrigin $origin, Purpose $purpose, ?IdentityReference $caller = null): array
    {
        $this->hold($origin);

        return $this->completed($purpose, $caller, null, $caller);
    }

    /**
     * Link the subject to the person, open the session on that link, and
     * complete a `reauthenticate`.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: string, 2: string, 3: ?\SineMacula\Laravel\Sso\Identities\IdentityReference}
     */
    private function reauthenticating(): array
    {
        $link = $this->hold(LinkOrigin::PROVISIONING);

        self::storageDatabase()->table(self::SESSIONS)->insert([
            'id'               => self::SESSION,
            'identity_id'      => $this->person->id,
            'link_id'          => $link->id,
            'authenticated_at' => self::EARLIER,
        ]);

        return $this->completed(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
    }

    /**
     * Start and complete a flow, and answer what redeems its code.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $session
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: string, 2: string, 3: ?\SineMacula\Laravel\Sso\Identities\IdentityReference}
     */
    private function completed(Purpose $purpose, ?IdentityReference $identity = null, ?string $session = null, ?IdentityReference $caller = null): array
    {
        $start      = $this->start($purpose, $identity, $session);
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());

        return [$purpose, (string) $completion->handoff?->code->reveal(), (string) $start->verifier?->reveal(), $caller];
    }

    /**
     * Link the subject to the person, in this process.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function hold(LinkOrigin $origin): Link
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
     * What a redeemer does: in one transaction on the storage connection, admit
     * the code, write the session a `sign_in` establishes, and write what it
     * accepted.
     *
     * @param  array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: string, 2: string, 3: ?\SineMacula\Laravel\Sso\Identities\IdentityReference}  $redeeming
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function redeemed(array $redeeming): RedemptionResult
    {
        return self::storageDatabase()->transaction(function () use ($redeeming): RedemptionResult {

            $answer = $this->admitted($redeeming);

            self::assertTrue($answer->isRedeemed());

            if ($redeeming[0] === Purpose::SIGN_IN) {
                self::storageDatabase()->table(self::SESSIONS)->insert([
                    'id'               => 'session-established',
                    'identity_id'      => (string) $answer->linkedIdentity?->id,
                    'link_id'          => $answer->linkId,
                    'authenticated_at' => self::EARLIER,
                ]);
            }

            self::storageDatabase()->table(self::EVIDENCE)->insert(['kind' => $redeeming[0]->value]);

            return $answer;
        });
    }

    /**
     * Admit the code, inside the transaction open.
     *
     * @param  array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: string, 2: string, 3: ?\SineMacula\Laravel\Sso\Identities\IdentityReference}  $redeeming
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function admitted(array $redeeming): RedemptionResult
    {
        return app(HandoffRedemption::class)->admit(...$this->redemptionArguments($redeeming));
    }

    /**
     * What a redemption is called with, by the name of each parameter.
     *
     * @param  array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: string, 2: string, 3: ?\SineMacula\Laravel\Sso\Identities\IdentityReference}  $redeeming
     * @return array<string, mixed>
     */
    private function redemptionArguments(array $redeeming): array
    {
        return [
            'purpose'      => $redeeming[0],
            'application'  => 'web',
            'connectionId' => $this->connection->id,
            'code'         => $redeeming[1],
            'verifier'     => $redeeming[2],
            'client'       => Clients::browser(),
            'caller'       => $redeeming[3],
        ];
    }

    /**
     * What the flow's redemption reports, once it commits.
     *
     * @param  string  $flow
     * @return list<class-string<\SineMacula\Laravel\Sso\Contracts\SsoEvent>>
     *
     * @throws \LogicException
     */
    private static function eventsOf(string $flow): array
    {
        return match ($flow) {
            self::RESERVED         => [LinkCreated::class, LinkActivated::class, HandoffRedeemed::class],
            self::LINKED           => [HandoffRedeemed::class],
            self::CREATING         => [LinkCreated::class, HandoffRedeemed::class],
            self::CONFIRMING       => [LinkConfirmed::class, HandoffRedeemed::class],
            self::REAUTHENTICATING => [HandoffRedeemed::class, ReauthenticationCompleted::class],
            default                => throw new \LogicException(sprintf('No flow is named [%s].', $flow)),
        };
    }

    /**
     * The session contract over the application's table, as an
     * implementation's: it writes the renewal through the storage connection,
     * then throws what the test set, if anything.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions
     */
    private function sessionContract(): ReauthenticationSessions
    {
        return new readonly class (self::SESSIONS, fn (): ?\Throwable => $this->renewalFailure) implements ReauthenticationSessions {
            /**
             * Constructor.
             *
             * @param  string  $table
             * @param  \Closure(): ?\Throwable  $failure
             */
            public function __construct(

                /** The application's table. */
                private string $table,

                /** What it throws once it has written. */
                private \Closure $failure,
            ) {}

            /**
             * Whether the identity holds the session.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            #[\Override]
            public function standing(IdentityReference $identity, string $sessionId, SsoConnection $connection): SessionStanding
            {
                unset($connection);

                $held = DB::connection(StorageConnection::name())->table($this->table)->where('id', $sessionId)->where('identity_id', $identity->id)->exists();

                return $held ? SessionStanding::SIGNED_IN : SessionStanding::NOT_SIGNED_IN;
            }

            /**
             * Lock the session, and whether it is bound to exactly the link.
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
                unset($application, $connection);

                $row = DB::connection(StorageConnection::name())->table($this->table)->where('id', $sessionId)->where('identity_id', $identity->id)->lockForUpdate()->first();

                return $row !== null && $row->link_id === $linkId ? SessionStanding::SIGNED_IN : SessionStanding::NOT_SIGNED_IN;
            }

            /**
             * Write the renewal, then fail when told to.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  \Carbon\CarbonImmutable  $authenticatedAt
             * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
             * @return void
             *
             * @throws \Throwable
             */
            #[\Override]
            public function renewAuthentication(IdentityReference $identity, string $sessionId, CarbonImmutable $authenticatedAt, ?AcceptedEvidence $evidence): void
            {
                unset($identity, $evidence);

                DB::connection(StorageConnection::name())->table($this->table)->where('id', $sessionId)->update(['authenticated_at' => $authenticatedAt->toIso8601String()]);

                $failure = ($this->failure)();

                if ($failure !== null) {
                    throw $failure;
                }
            }
        };
    }
}
