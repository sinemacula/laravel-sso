<?php

declare(strict_types = 1);

namespace Tests\Feature\Provisioning;

use Illuminate\Database\Connection as DatabaseConnection;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager as TestingTransactionsManager;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningResult;
use Tests\Concerns\FailsDatabaseStatements;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Feature tests for the provisioning helper's client and its claim retries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProvisioningHelper::class)]
final class ProvisioningHelperTest extends LinkingTestCase
{
    use FailsDatabaseStatements;

    /** @var list<\SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus> The helper's answers, in order. */
    private array $statuses = [];

    /**
     * Make the result unmatched by any verified domain, so it is offered for
     * provisioning.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->matcher->match = LinkEmailMatch::none();

        $this->usePackageTables();
    }

    /**
     * The link the helper creates is reported with the client it was given.
     *
     * @return void
     */
    public function testTheLinkIsReportedWithTheClientGiven(): void
    {
        $client = new ClientContext('192.0.2.44', 'Provisioner/1.0');

        $this->start();

        Event::listen(SsoEvent::class, function (SsoEvent $event) use ($client): void {
            if (!$event instanceof ResultUnlinked) {
                return;
            }

            self::assertTrue(app(ProvisioningHelper::class)->link($event->grant, $event->result, $this->person, $client)->isCreated());
        });

        $this->app?->instance('request', Request::create('/', 'POST', server: ['REMOTE_ADDR' => '198.51.100.9', 'HTTP_USER_AGENT' => 'Served/1.0']));
        $this->startRecordingEvents();

        self::assertTrue($this->complete()->isCompleted());

        $this->assertEventSequence([ResultVerified::class, ResultUnlinked::class, LinkCreated::class, HandoffIssued::class]);

        $created = $this->recordedEvents()[2];

        self::assertInstanceOf(LinkCreated::class, $created);
        self::assertSame(LinkOrigin::PROVISIONING, $created->origin);
        self::assertSame(['192.0.2.44', 'Provisioner/1.0'], [$created->context()->ip, $created->context()->userAgent]);
        self::assertSame($this->person->id, $created->context()->identityId);
        self::assertSame([Clients::IP, Clients::USER_AGENT], [$this->recordedEvents()[0]->context()->ip, $this->recordedEvents()[0]->context()->userAgent]);
    }

    /**
     * A listener retrying its whole transaction after a deadlock provisions
     * once.
     *
     * @return void
     */
    public function testAListenerRetryingItsTransactionProvisions(): void
    {
        $this->start();
        $this->deadlockStatement(self::onTable('insert', 'sso_links'));

        $this->onOffer(function (ResultUnlinked $event): void {
            self::storage()->transaction(fn (): ProvisioningResult => $this->provision($event), 3);
        });

        $this->startRecordingEvents();

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame(1, $this->databaseFailuresFired());
        self::assertSame([ProvisioningStatus::CREATED], $this->statuses);
        self::assertSame($this->person->id, Link::query()->sole()->identity_id);
        $this->assertEventSequence([ResultVerified::class, ResultUnlinked::class, LinkCreated::class, HandoffIssued::class]);
    }

    /**
     * With no listener transaction, the helper's own rollback allows a retry.
     *
     * @return void
     */
    public function testWithNoListenerTransactionTheHelpersOwnRollbackAllowsARetry(): void
    {
        $this->start();
        $this->deadlockStatement(self::onTable('insert', 'sso_links'));

        $this->onOffer(function (ResultUnlinked $event): void {
            try {
                $this->provision($event);

                self::fail('The deadlock was not injected.');
            } catch (\PDOException $exception) {
                self::assertTrue(self::isInjectedFailure($exception));
            }

            $this->provision($event);
        });

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame([ProvisioningStatus::CREATED], $this->statuses);
        self::assertSame(1, Link::query()->count());
    }

    /**
     * The claim is bound before the helper's savepoint begins.
     *
     * @return void
     */
    public function testTheClaimIsBoundBeforeTheHelpersSavepointBegins(): void
    {
        $this->start();

        $database = self::storage();
        $failed   = false;

        $this->onOffer(function (ResultUnlinked $event) use ($database, &$failed): void {

            $database->beforeStartingTransaction(static function (DatabaseConnection $connection) use (&$failed): void {

                if ($failed || $connection->transactionLevel() !== 1) {
                    return;
                }

                $failed = true;

                throw new QueryException((string) $connection->getName(), 'savepoint trans2', [], new \PDOException('Deadlock found when trying to get lock'));
            });

            $database->transaction(fn (): ProvisioningResult => $this->provision($event), 3);
        });

        self::assertTrue($this->complete()->isCompleted());
        self::assertTrue($failed);
        self::assertSame([ProvisioningStatus::CREATED], $this->statuses);
    }

    /**
     * A claim not yet bound to the helper's transaction gets no second use.
     *
     * @return void
     */
    public function testAClaimNotYetBoundGetsNoSecondUse(): void
    {
        $this->start();

        $reentered = false;

        $this->onOffer(function (ResultUnlinked $event) use (&$reentered): void {

            Event::listen(TransactionBeginning::class, function () use ($event, &$reentered): void {

                if ($reentered) {
                    return;
                }

                $reentered = true;

                $this->provision($event, new IdentityReference('App\Models\User', '8'));
            });

            $this->provision($event);
        });

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame([ProvisioningStatus::GRANT_INVALID, ProvisioningStatus::CREATED], $this->statuses);
        self::assertSame($this->person->id, Link::query()->sole()->identity_id);
    }

    /**
     * A committed claim cannot be claimed again.
     *
     * @return void
     */
    public function testACommittedClaimCannotBeClaimedAgain(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {

            $database = self::storage();

            $database->transaction(function () use ($database, $event): void {

                $database->afterCommit(function () use ($event): void {
                    $this->provision($event);
                });

                $this->provision($event);
            });

            $this->provision($event);
        });

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame([ProvisioningStatus::CREATED, ProvisioningStatus::GRANT_INVALID, ProvisioningStatus::GRANT_INVALID], $this->statuses);
        self::assertSame(1, Link::query()->count());
    }

    /**
     * A rolled-back savepoint leaves the grant claimed.
     *
     * @return void
     */
    public function testARolledBackSavepointLeavesTheGrantClaimed(): void
    {
        $this->start();
        $this->failStatement(self::onTable('insert', 'sso_links'));

        $this->onOffer(function (ResultUnlinked $event): void {
            self::storage()->transaction(function () use ($event): void {
                try {
                    $this->provision($event);
                } catch (QueryException $exception) {
                    self::assertTrue(self::isInjectedFailure($exception));
                }

                $this->provision($event);
            });
        });

        self::assertSame(FailureReason::UNLINKED, $this->complete()->reason);
        self::assertSame([ProvisioningStatus::GRANT_INVALID], $this->statuses);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * A refusal spends the grant for good.
     *
     * @return void
     */
    public function testARefusalCannotBeRetried(): void
    {
        app(LinkStore::class)->create($this->connection, new LinkSubject(VerifyingDriver::ISSUER, 'another-subject'), $this->person, LinkOrigin::LINK_PURPOSE, Clients::browser());

        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {

            $attempts = 0;

            self::storage()->transaction(function () use ($event, &$attempts): void {

                $this->provision($event);

                if (++$attempts === 1) {
                    throw new DeadlockException('Deadlock found when trying to get lock');
                }
            }, 3);
        });

        self::assertSame(FailureReason::UNLINKED, $this->complete()->reason);
        self::assertSame([ProvisioningStatus::LINK_LIMIT_REACHED, ProvisioningStatus::GRANT_INVALID], $this->statuses);
        self::assertSame(1, Link::query()->count());
    }

    /**
     * A claim refused for another result spends the grant for good.
     *
     * @return void
     */
    public function testAWrongResultCannotBeRetried(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {

            $attempts = 0;

            self::storage()->transaction(function () use ($event, &$attempts): void {

                if (++$attempts === 1) {
                    $this->statuses[] = app(ProvisioningHelper::class)->link($event->grant, clone $event->result, $this->person, Clients::browser())->status;

                    throw new DeadlockException('Deadlock found when trying to get lock');
                }

                $this->provision($event);
            }, 3);
        });

        self::assertSame(FailureReason::UNLINKED, $this->complete()->reason);
        self::assertSame([ProvisioningStatus::GRANT_WRONG_RESULT, ProvisioningStatus::GRANT_INVALID], $this->statuses);
    }

    /**
     * The testing traits' wrapping transaction is not the listener's.
     *
     * @return void
     */
    public function testTheTestingWrapperIsNoTransactionOfTheListener(): void
    {
        $this->start();
        $this->deadlockStatement(self::onTable('insert', 'sso_links'));

        $this->onOffer(function (ResultUnlinked $event): void {

            $database = self::storage();
            $original = app('db.transactions');
            $testing  = new TestingTransactionsManager([$database->getName()]);

            self::assertInstanceOf(DatabaseTransactionsManager::class, $original);

            $this->app?->instance('db.transactions', $testing);
            $database->setTransactionManager($testing);
            $database->beginTransaction();

            try {
                try {
                    $this->provision($event);
                } catch (DeadlockException $exception) {
                    self::assertTrue(self::isInjectedFailure($exception));
                }

                $this->provision($event);
                $database->commit();
            } finally {
                $this->app?->instance('db.transactions', $original);
                $database->setTransactionManager($original);
            }
        });

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame([ProvisioningStatus::CREATED], $this->statuses);
        self::assertSame(1, Link::query()->count());
    }

    /**
     * A commit Laravel 12 fails without telling the manager leaves the grant
     * spent.
     *
     * @return void
     */
    public function testACommitTheManagerWasNotToldFailedLeavesTheGrantSpent(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {

            self::storage()->beginTransaction();

            $this->provision($event);

            self::endUnreported();

            $this->provision($event);
        });

        self::assertSame(FailureReason::UNLINKED, $this->complete()->reason);
        self::assertSame([ProvisioningStatus::CREATED, ProvisioningStatus::GRANT_INVALID], $this->statuses);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Rows of `[inTransaction]`: with no listener transaction, and inside one
     * that commits.
     *
     * @return iterable<string, array{bool}>
     */
    public static function provideListenerTransactions(): iterable
    {
        yield 'with no transaction' => [false];
        yield 'inside its transaction' => [true];
    }

    /**
     * A stale record left by an unreported failed commit does not unspend a
     * committed claim.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('provideListenerTransactions')]
    public function testACommittedClaimStaysSpentPastARecordAFailedCommitLeft(bool $inTransaction): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event) use ($inTransaction): void {

            $database = self::storage();

            $database->beginTransaction();

            self::endUnreported();

            if ($inTransaction) {
                $database->transaction(fn (): ProvisioningResult => $this->provision($event));
            } else {
                $this->provision($event);
            }

            $database->beginTransaction();
            $database->rollBack();

            self::assertFalse($event->grant->isUsable());

            $this->provision($event);
        });

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame([ProvisioningStatus::CREATED, ProvisioningStatus::GRANT_INVALID], $this->statuses);
        self::assertSame(1, Link::query()->count());
    }

    /**
     * A failed commit allows a retry only where Laravel tells the manager (13,
     * not 12).
     *
     * @return void
     */
    public function testAFailedCommitAllowsARetryOnlyWhereTheManagerIsTold(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {

            $this->failCommit();

            try {
                self::storage()->transaction(fn (): ProvisioningResult => $this->provision($event));

                self::fail('The commit did not fail.');
            } catch (QueryException $exception) {
                self::assertTrue(self::isInjectedFailure($exception));
            }

            self::storage()->transaction(fn (): ProvisioningResult => $this->provision($event));
        });

        $told = version_compare(app()->version(), '13', '>=');

        self::assertSame($told, $this->complete()->isCompleted());
        self::assertSame([ProvisioningStatus::CREATED, $told ? ProvisioningStatus::CREATED : ProvisioningStatus::GRANT_INVALID], $this->statuses);
        self::assertSame($told ? 1 : 0, Link::query()->count());
    }

    /**
     * A grant released by rollback is void once the dispatch ends.
     *
     * @return void
     */
    public function testAReleasedGrantIsVoidOnceTheDispatchEnds(): void
    {
        $this->start();

        $kept = null;

        $this->onOffer(function (ResultUnlinked $event) use (&$kept): void {

            $kept = $event;

            self::storage()->beginTransaction();
            $this->provision($event);
            self::storage()->rollBack();

            self::assertTrue($event->grant->isUsable());
        });

        self::assertSame(FailureReason::UNLINKED, $this->complete()->reason);
        self::assertInstanceOf(ResultUnlinked::class, $kept);
        self::assertFalse($kept->grant->isUsable());
        self::assertSame(ProvisioningStatus::GRANT_INVALID, $this->provision($kept)->status);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Listen for the result being offered, after the events are recorded.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Events\ResultUnlinked): void  $listener
     * @return void
     */
    private function onOffer(\Closure $listener): void
    {
        Event::listen(SsoEvent::class, static function (SsoEvent $event) use ($listener): void {

            if (!$event instanceof ResultUnlinked) {
                return;
            }

            $listener($event);
        });
    }

    /**
     * Ask the helper to link the event's result to the person and keep its
     * status.
     *
     * @param  \SineMacula\Laravel\Sso\Events\ResultUnlinked  $event
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Provisioning\ProvisioningResult
     *
     * @throws \Throwable
     */
    private function provision(ResultUnlinked $event, ?IdentityReference $identity = null): ProvisioningResult
    {
        $answer = app(ProvisioningHelper::class)->link($event->grant, $event->result, $identity ?? $this->person, Clients::browser());

        $this->statuses[] = $answer->status;

        return $answer;
    }

    /**
     * The storage connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private static function storage(): DatabaseConnection
    {
        /** @var \Illuminate\Database\Connection */
        return DB::connection(StorageConnection::name());
    }

    /**
     * End the outermost transaction as Laravel 12 ends a failed commit, leaving
     * the manager's record current.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private static function endUnreported(): void
    {
        $database = self::storage();
        $manager  = app('db.transactions');

        self::assertInstanceOf(DatabaseTransactionsManager::class, $manager);

        $database->unsetTransactionManager();

        try {
            $database->rollBack(0);
        } finally {
            $database->setTransactionManager($manager);
        }
    }
}
