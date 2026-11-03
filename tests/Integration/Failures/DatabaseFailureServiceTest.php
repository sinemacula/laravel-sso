<?php

declare(strict_types = 1);

namespace Tests\Integration\Failures;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Discovery\DiscoveryService;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestConsumption;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\FailsDatabaseStatements;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * A failing statement or commit at a service boundary is a server error
 * (SSO-11.4): the `QueryException` reaches the caller from every step of a
 * flow, never `failed`, `request_unknown`, `connection_unavailable`, an invalid
 * response or a failed redemption, and no failure event is reported for it.
 *
 * Each step is reached for certain and fails once, at a named occurrence of a
 * named statement: a request's consumption (T1); the locked rechecks and the
 * issuance of the completion's transaction (T2), armed as the driver validates,
 * which is after T1 has committed; the continuation's issuance (T3), armed as
 * the unlinked result is offered, which is after T2 has committed; a link's
 * creation by the provisioning helper; a redemption, with its activation; and a
 * discovery start, at each step past its match. The commits of T1 and T3 fail
 * in their turn too. `CompletionRollbackTest` and `RedemptionRollbackTest` fail
 * the other writes and commits of T2 and of a redemption, and compare every row
 * stored, so they are not repeated here.
 *
 * What survives is what the transaction owns and no more: T1 unconsumed and
 * able to go again when T1 fails; T1 standing when T2 fails, and T2 standing
 * when T3 fails, with T2's own after-commit event reported; a redemption wholly
 * undone, the code unspent and the activation gone, so it runs again and
 * succeeds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequestService::class)]
#[CoversClass(CompletionService::class)]
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(RequestConsumption::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(DiscoveryService::class)]
#[CoversClass(ProvisioningHelper::class)]
final class DatabaseFailureServiceTest extends LinkingTestCase
{
    use FailsDatabaseStatements;

    /** @var string The session a `reauthenticate` is started on. */
    private const string SESSION = 'session-of-the-failure-test';

    /**
     * Let every identity link, with a fresh caller.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
    }

    /**
     * Rows of `[verb, table, occurrence]`: each statement of a start.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideStartStatements(): iterable
    {
        yield 'counting the attempt' => ['update', 'sso_rate_limits', 1];
        yield 'reading the connection' => ['select', 'sso_connections', 1];
        yield 'locking the connection' => ['select', 'sso_connections', 2];
        yield 'storing the request' => ['insert', 'sso_authorization_requests', 1];
        yield 'raising the flows version' => ['update', 'sso_connections', 1];
    }

    /**
     * A start that fails at any statement propagates, and stores and reports
     * nothing.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideStartStatements')]
    public function testAStartPropagates(string $verb, string $table, int $occurrence): void
    {
        $this->failStatement(self::onTable($verb, $table), $occurrence);

        $this->assertServerError(fn (): StartResult => app(AuthorizationRequestService::class)->start('web', Purpose::SIGN_IN, $this->connection->id));

        self::assertSame(0, AuthorizationRequest::query()->useWritePdo()->count());

        $this->assertNoEvents();
    }

    /**
     * A failed commit of a start stores and reports nothing.
     *
     * @return void
     */
    public function testAStartsFailedCommitPropagates(): void
    {
        $this->failCommit();

        $this->assertServerError(fn (): StartResult => app(AuthorizationRequestService::class)->start('web', Purpose::SIGN_IN, $this->connection->id));

        self::assertSame(0, AuthorizationRequest::query()->useWritePdo()->count());

        $this->assertNoEvents();
    }

    /**
     * Rows of `[verb, table, occurrence]`: each statement of a consumption.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideConsumptionStatements(): iterable
    {
        yield 'locking the connection' => ['select', 'sso_connections', 2];
        yield 'locking the request' => ['select', 'sso_authorization_requests', 1];
        yield 'recording the request' => ['insert', 'sso_single_use_keys', 1];
        yield 'consuming the request' => ['update', 'sso_authorization_requests', 1];
    }

    /**
     * A failure in T1 propagates and leaves the request unconsumed and
     * unrecorded, so the same answer goes again and completes.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideConsumptionStatements')]
    public function testAFailedConsumptionLeavesTheRequestToGoAgain(string $verb, string $table, int $occurrence): void
    {
        $start = $this->start();

        $this->startRecordingEvents();
        $this->failStatement(self::onTable($verb, $table), $occurrence);

        $this->assertServerError(fn (): mixed => $this->complete());
        $this->assertUnconsumed($start);
        $this->assertNoEvents();

        self::assertTrue($this->complete()->isCompleted());
    }

    /**
     * A failed commit of T1 leaves the request unconsumed as well.
     *
     * @return void
     */
    public function testAFailedCommitOfTheConsumptionLeavesTheRequestToGoAgain(): void
    {
        $start = $this->start();

        $this->startRecordingEvents();
        $this->failCommit();

        $this->assertServerError(fn (): mixed => $this->complete());
        $this->assertUnconsumed($start);
        $this->assertNoEvents();

        self::assertTrue($this->complete()->isCompleted());
    }

    /**
     * Rows of `[verb, table, occurrence]`: each locked read of T2, in a
     * completion that reserves a link, and its issuance of the code. The first
     * read of a link and of a domain is the plain one before the transaction.
     * `CompletionRollbackTest` fails T2's other writes and its commit,
     * comparing every stored row.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideLockedStatements(): iterable
    {
        yield 'reading the subject before the locks' => ['select', 'sso_links', 1];
        yield 'locking the connection' => ['select', 'sso_connections', 1];
        yield 'locking the domain' => ['select', 'sso_domains', 2];
        yield 'locking the request' => ['select', 'sso_authorization_requests', 1];
        yield 'resolving the link' => ['select', 'sso_links', 2];
        yield 'issuing the code' => ['insert', 'sso_handoff_codes', 1];
    }

    /**
     * A failure in T2 propagates: T1 stands, and nothing of T2 does, its code,
     * its reservation and its events.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideLockedStatements')]
    public function testAFailureInTheLockedTransactionRollsItBack(string $verb, string $table, int $occurrence): void
    {
        $start = $this->start();

        $this->startRecordingEvents();

        $this->verifying->onComplete = fn () => $this->failStatement(self::onTable($verb, $table), $occurrence);

        $this->assertServerError(fn (): mixed => $this->complete());
        $this->assertConsumedAndUnfinished($start);

        self::assertSame(0, Link::query()->useWritePdo()->count());

        $this->assertNoEvents();
    }

    /**
     * Rows of `[verb, table, occurrence]`: each statement of T3, in the only
     * completion failed here or anywhere that ends on an unlinked handoff.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideContinuationStatements(): iterable
    {
        yield 'locking the connection' => ['select', 'sso_connections', 1];
        yield 'locking the request' => ['select', 'sso_authorization_requests', 1];
        yield 'issuing the code' => ['insert', 'sso_handoff_codes', 1];
        yield 'raising the connection' => ['update', 'sso_connections', 1];
        yield 'stamping the request' => ['update', 'sso_authorization_requests', 1];
    }

    /**
     * A failure in T3 propagates: T2 stands, with `verified_at` and the events
     * already reported, and nothing of T3 does.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideContinuationStatements')]
    public function testAFailureInTheContinuationLeavesTheFirstTransaction(string $verb, string $table, int $occurrence): void
    {
        $start = $this->unlinkedStart();

        Event::listen(ResultUnlinked::class, fn () => $this->failStatement(self::onTable($verb, $table), $occurrence));

        $this->assertServerError(fn (): mixed => $this->complete());
        $this->assertVerifiedAndUnfinished($start);
    }

    /**
     * A failed commit of T3 leaves what a failure inside it leaves.
     *
     * @return void
     */
    public function testAFailedCommitOfTheContinuationLeavesTheFirstTransaction(): void
    {
        $start = $this->unlinkedStart();

        Event::listen(ResultUnlinked::class, fn () => $this->failCommit());

        $this->assertServerError(fn (): mixed => $this->complete());
        $this->assertVerifiedAndUnfinished($start);
    }

    /**
     * A failed write of the provisioning helper ends the completion as a server
     * error, not a refusal, with no link and the grant void.
     *
     * @return void
     */
    public function testAFailedProvisioningWritePropagates(): void
    {
        $start = $this->unlinkedStart();
        $grant = null;

        Event::listen(ResultUnlinked::class, function (ResultUnlinked $event) use (&$grant): void {

            $grant = $event->grant;

            $this->failStatement(self::onTable('insert', 'sso_links'));

            app(ProvisioningHelper::class)->link($event->grant, $event->result, $this->person);
        });

        $this->assertServerError(fn (): mixed => $this->complete());
        $this->assertVerifiedAndUnfinished($start, [ResultVerified::class]);

        self::assertFalse($grant?->isUsable());
        self::assertSame(0, Link::query()->useWritePdo()->count());
    }

    /**
     * Rows of `[verb, table, occurrence]`: each read and lock of a redemption,
     * and its activation of the reservation. `RedemptionRollbackTest` fails its
     * other writes and its commit, comparing every stored row.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideRedemptionStatements(): iterable
    {
        yield 'counting the attempt' => ['update', 'sso_rate_limits', 1];
        yield 'finding the code' => ['select', 'sso_handoff_codes', 1];
        yield 'reading the tenant' => ['select', 'sso_connections', 1];
        yield 'locking the connection' => ['select', 'sso_connections', 2];
        yield 'locking the code' => ['select', 'sso_handoff_codes', 2];
        yield 'activating the reservation' => ['update', 'sso_links', 1];
    }

    /**
     * A failure anywhere in a redemption propagates, never as a failed one: the
     * code is unspent, the reservation not activated and nothing reported, so
     * the same code and verifier redeem when tried again.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideRedemptionStatements')]
    public function testAFailedRedemptionIsUndoneWhole(string $verb, string $table, int $occurrence): void
    {
        $start      = $this->start();
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());

        $this->startRecordingEvents();
        $this->failStatement(self::onTable($verb, $table), $occurrence);

        $this->assertServerError(fn (): RedemptionResult => $this->admit($completion, $start));
        $this->assertCodeUnspent($start);
        $this->assertNoEvents();

        self::assertSame(LinkState::RESERVED, Link::query()->useWritePdo()->sole()->state);
        self::assertTrue($this->admit($completion, $start)->isRedeemed());
        self::assertSame(LinkState::ACTIVE, Link::query()->useWritePdo()->sole()->state);
    }

    /**
     * Rows of `[verb, table, occurrence]`: each statement a standalone `link`
     * writes.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideLinkStatements(): iterable
    {
        yield 'consuming the code' => ['update', 'sso_handoff_codes', 1];
        yield 'creating the link' => ['insert', 'sso_links', 1];
    }

    /**
     * A standalone `link` that fails creates no link and leaves the code
     * unspent, its transaction its own.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideLinkStatements')]
    public function testAFailedLinkLeavesNoLink(string $verb, string $table, int $occurrence): void
    {
        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();
        $code       = (string) $completion->handoff?->code->reveal();
        $verifier   = (string) $start->verifier?->reveal();

        $this->startRecordingEvents();
        $this->failStatement(self::onTable($verb, $table), $occurrence);

        $redeem = fn (): RedemptionResult => app(HandoffRedemption::class)->redeem(Purpose::LINK, 'web', $this->connection->id, $code, $verifier, $this->person);

        $this->assertServerError($redeem);
        $this->assertCodeUnspent($start);
        $this->assertNoEvents();

        self::assertSame(0, Link::query()->useWritePdo()->count());
        self::assertTrue($redeem()->isRedeemed());
    }

    /**
     * A `reauthenticate` that fails to consume its code propagates, with the
     * code unspent and the session not renewed, and runs again.
     *
     * @return void
     */
    public function testAFailedReauthenticationRenewsNothing(): void
    {
        $sessions   = $this->sessionsOnALink();
        $start      = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
        $completion = $this->complete();

        $this->startRecordingEvents();
        $this->failStatement(self::onTable('update', 'sso_handoff_codes'));

        $this->assertServerError(fn (): RedemptionResult => $this->admit($completion, $start, Purpose::REAUTHENTICATE));
        $this->assertCodeUnspent($start);
        $this->assertNoEvents();

        self::assertSame(0, $sessions->renewals());
        self::assertTrue($this->admit($completion, $start, Purpose::REAUTHENTICATE)->isRedeemed());
        self::assertSame(1, $sessions->renewals());
    }

    /**
     * Rows of `[verb, table, occurrence]`: what a discovery start reads and
     * writes, past the domain it matches.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideDiscoveryStatements(): iterable
    {
        yield 'finding the domain' => ['select', 'sso_domains', 1];
        yield 'reading the connection the domain names' => ['select', 'sso_connections', 1];
        yield 'storing the request' => ['insert', 'sso_authorization_requests', 1];
    }

    /**
     * A discovery start that cannot read the domain or go on from it
     * propagates, and is never the fallback a miss answers.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideDiscoveryStatements')]
    public function testADiscoveryStartPropagates(string $verb, string $table, int $occurrence): void
    {
        config()->set('sso.features.discovery', true);
        config()->set('sso.discovery.minimum_duration_milliseconds', 50);
        config()->set('sso.applications.discovering', [
            'redirect_uri'     => 'https://app.example.com/sso',
            'external_sign_in' => true,
            'discovery'        => ['enabled' => true, 'fallback_url' => 'https://app.example.com/sign-in'],
        ]);

        $this->failStatement(self::onTable($verb, $table), $occurrence);

        $this->assertServerError(static fn (): StartResult => app(DiscoveryService::class)->start('discovering', Purpose::SIGN_IN, 'person@example.com'));

        self::assertSame(0, AuthorizationRequest::query()->useWritePdo()->count());

        $this->assertNoEvents();
    }

    /**
     * Assert the call throws the one injected failure as a `QueryException`,
     * with no transaction left open and no failure event reported.
     *
     * @param  \Closure(): mixed  $call
     * @return void
     */
    private function assertServerError(\Closure $call): void
    {
        try {
            $call();
        } catch (QueryException $exception) {

            self::assertTrue(self::isInjectedFailure($exception));
            self::assertSame(1, $this->databaseFailuresFired());
            self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());

            $this->assertNoFailure();

            return;
        }

        self::fail('The database failure was answered as a result.');
    }

    /**
     * A `sign_in` start whose result resolves to nothing and holds no linking
     * email, so its completion stops at the provisioning boundary, and goes on
     * to an unlinked handoff.
     *
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    private function unlinkedStart(): StartResult
    {
        config()->set('sso.applications.web.unlinked_handoffs', true);

        $this->verifying->claims = $this->claims(null);

        $start = $this->start();

        $this->startRecordingEvents();

        return $start;
    }

    /**
     * The stored request of the start.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function requestOf(StartResult $start): AuthorizationRequest
    {
        return AuthorizationRequest::query()->useWritePdo()->where('reference', (string) $start->reference?->value)->sole();
    }

    /**
     * Assert the request is as T1's rollback leaves it.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return void
     */
    private function assertUnconsumed(StartResult $start): void
    {
        self::assertNull($this->requestOf($start)->consumed_at);
        self::assertSame(0, SingleUseKey::query()->useWritePdo()->where('namespace', RequestConsumption::NAMESPACE)->count());
    }

    /**
     * Assert the request is consumed, T1 having committed, and neither verified
     * nor finished, with no code.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return void
     */
    private function assertConsumedAndUnfinished(StartResult $start): void
    {
        $request = $this->requestOf($start);

        self::assertNotNull($request->consumed_at);
        self::assertNull($request->verified_at);
        self::assertNull($request->completed_at);
        self::assertSame(0, HandoffCode::query()->useWritePdo()->count());
    }

    /**
     * Assert the request is verified, T2 having committed and reported, and not
     * finished, with no code. A listener of `ResultUnlinked` that throws comes
     * before the recorder, which listens to the interface, so it passes the
     * events the recorder saw.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  list<class-string<\SineMacula\Laravel\Sso\Contracts\SsoEvent>>  $events
     * @return void
     */
    private function assertVerifiedAndUnfinished(StartResult $start, array $events = [ResultVerified::class, ResultUnlinked::class]): void
    {
        $request = $this->requestOf($start);

        self::assertNotNull($request->verified_at);
        self::assertNull($request->completed_at);
        self::assertSame(0, HandoffCode::query()->useWritePdo()->count());

        $this->assertEventSequence($events);
    }

    /**
     * Assert the code of the start is unspent, in its row and in the store.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return void
     */
    private function assertCodeUnspent(StartResult $start): void
    {
        self::assertNull(HandoffCode::query()->useWritePdo()->where('request_reference', (string) $start->reference?->value)->sole()->redeemed_at);
        self::assertSame(0, SingleUseKey::query()->useWritePdo()->where('namespace', HandoffRedemption::NAMESPACE)->count());
    }

    /**
     * Link the person to the driver's subject, and bind a session contract with
     * one session on that link.
     *
     * @return \Tests\Fixtures\Linking\RecordingSessions
     */
    private function sessionsOnALink(): RecordingSessions
    {
        $creation = app(LinkStore::class)->create($this->connection, new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT), $this->person, LinkOrigin::PROVISIONING);

        self::assertTrue($creation->isCreated());

        $sessions = new RecordingSessions($creation->link?->id);

        $this->app?->instance(ReauthenticationSessions::class, $sessions);

        return $sessions;
    }
}
