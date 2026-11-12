<?php

declare(strict_types = 1);

namespace Tests\Integration\Combined;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RaceFlows;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Integration tests for what a failure in each completion transaction rolls
 * back.
 *
 * Transaction names follow `docs/design/transaction-ownership.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(ProvisioningHelper::class)]
final class CompletionRollbackTest extends LinkingTestCase
{
    use RaceFlows;

    /** @var string The table the listener keeps its identities and memberships in. */
    private const string IDENTITIES = 'combined_rollback_identities';

    /** @var string A failure in a reservation's preparation. */
    private const string RESERVED = 'reserved';

    /** @var string A failure in a linked result's preparation. */
    private const string LINKED = 'linked';

    /** @var string What an issuer that throws says. */
    private const string ISSUER_FAILURE = 'The handoff could not be issued.';

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The new identity the listener provisions. */
    private IdentityReference $provisioned;

    /**
     * Bind a fresh caller, record assertions against replay, and create the
     * listener's table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->provisioned = new IdentityReference('App\Models\User', 'provisioned');

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $this->verifying->replay = ReplayRecord::samlAssertion($this->connection->id, VerifyingDriver::ISSUER, 'assertion-1', $this->clock->now()->addMinutes(5));

        self::storageDatabase()->getSchemaBuilder()->create(self::IDENTITIES, static function (Blueprint $table): void {
            $table->id();
            $table->string('kind');
        });
    }

    /**
     * Drop the listener's table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::storageDatabase()->getSchemaBuilder()->dropIfExists(self::IDENTITIES);

        parent::tearDown();
    }

    /**
     * Rows of `[the flow, the verb, the table's key, the occurrence]`; a `null`
     * verb fails the commit.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: ?string, 3: int}>
     */
    public static function providePreparationFailures(): iterable
    {
        yield 'a reservation, at the identity guard' => [self::RESERVED, 'insert', 'identity_guards.table', 1];
        yield 'a reservation, at the replay record' => [self::RESERVED, 'insert', 'single_use.table', 1];
        yield 'a reservation, at the reservation' => [self::RESERVED, 'insert', 'links.table', 1];
        yield 'a reservation, at its links version' => [self::RESERVED, 'update', 'connections.table', 1];
        yield 'a reservation, at the code' => [self::RESERVED, 'insert', 'handoff_codes.table', 1];
        yield 'a reservation, at its flows version' => [self::RESERVED, 'update', 'connections.table', 2];
        yield 'a reservation, at binding the code' => [self::RESERVED, 'update', 'links.table', 1];
        yield 'a reservation, at completed_at' => [self::RESERVED, 'update', 'authorization_requests.table', 1];
        yield 'a reservation, at its commit' => [self::RESERVED, null, null, 1];
        yield 'a linked result, at the replay record' => [self::LINKED, 'insert', 'single_use.table', 1];
        yield 'a linked result, at the code' => [self::LINKED, 'insert', 'handoff_codes.table', 1];
        yield 'a linked result, at completed_at' => [self::LINKED, 'update', 'authorization_requests.table', 1];
        yield 'a linked result, at its commit' => [self::LINKED, null, null, 1];
    }

    /**
     * Rolls back T2 of a finishing flow; T1's consumption stays.
     *
     * @param  string  $flow
     * @param  ?string  $verb
     * @param  ?string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('providePreparationFailures')]
    public function testPreparationRollsBackAlone(string $flow, ?string $verb, ?string $table, int $occurrence): void
    {
        if ($flow === self::LINKED) {
            $this->hold($this->person);
        }

        $this->start();
        $this->startRecordingEvents();

        $before = $this->armedAfterConsumption($verb, $table, $occurrence);

        $this->assertCompletionFails();

        self::assertSame(1, $this->databaseFailuresFired());
        self::assertSame(0, self::storageDatabase()->transactionLevel());
        self::assertSame($before->getArrayCopy(), self::storedRows([self::IDENTITIES]));
        $this->assertNoEvents();

        self::assertNotNull($this->storedRequest()->consumed_at);
        self::assertNull($this->storedRequest()->completed_at);
        self::assertSame(FailureReason::REQUEST_UNKNOWN, $this->complete()->reason);
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::REQUEST_UNKNOWN);
    }

    /**
     * Rows of `[the issuer, whether it wrote its code before it threw]`.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideIssuers(): iterable
    {
        yield 'an issuer that throws having written nothing' => [false];
        yield 'an issuer that throws having written its code' => [true];
    }

    /**
     * Rolls back T2 of a reservation when the issuer throws; T1 stays.
     *
     * @param  bool  $writes
     * @return void
     */
    #[DataProvider('provideIssuers')]
    public function testAThrowingIssuerRollsBackAReservation(bool $writes): void
    {
        $this->start();
        $this->startRecordingEvents();

        $this->app?->instance(HandoffIssuer::class, $this->throwingIssuer($writes));

        $before = $this->armedAfterConsumption(null, null, 0);

        $this->assertCompletionThrowsTheIssuersFailure();

        self::assertSame($before->getArrayCopy(), self::storedRows([self::IDENTITIES]));
        self::assertNotNull($this->storedRequest()->consumed_at);
        self::assertNull($this->storedRequest()->completed_at);
        $this->assertNoEvents();
    }

    /**
     * Rows of `[the verb, the table's key]`; a `null` verb fails the commit.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideSuspensionFailures(): iterable
    {
        yield 'at the suspension' => ['update', 'links.table'];
        yield 'at completed_at' => ['update', 'authorization_requests.table'];
        yield 'at its commit' => [null, null];
    }

    /**
     * Rolls back T2 that latched a suspension; the link stays active.
     *
     * @param  ?string  $verb
     * @param  ?string  $table
     * @return void
     */
    #[DataProvider('provideSuspensionFailures')]
    public function testASuspensionLatchedInPreparationRollsBack(?string $verb, ?string $table): void
    {
        $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        $this->start();
        $this->startRecordingEvents();

        $before = $this->armedAfterConsumption($verb, $table, 1);

        $this->assertCompletionFails();

        self::assertSame($before->getArrayCopy(), self::storedRows([self::IDENTITIES]));
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        self::assertNull($this->storedRequest()->completed_at);
        $this->assertNoEvents();
    }

    /**
     * Rows of `[the verb, the table's key]`; a `null` verb fails the commit.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideBoundaryFailures(): iterable
    {
        yield 'at the replay record' => ['insert', 'single_use.table'];
        yield 'at verified_at' => ['update', 'authorization_requests.table'];
        yield 'at its commit' => [null, null];
    }

    /**
     * Rolls back T2 stopping at the provisioning boundary; the result is never
     * offered.
     *
     * @param  ?string  $verb
     * @param  ?string  $table
     * @return void
     */
    #[DataProvider('provideBoundaryFailures')]
    public function testPreparationStoppingAtTheBoundaryRollsBackAlone(?string $verb, ?string $table): void
    {
        $this->matcher->match = LinkEmailMatch::none();

        $this->start();
        $this->startRecordingEvents();

        $offered = false;

        $this->onOffer(static function () use (&$offered): void {
            $offered = true;
        });

        $before = $this->armedAfterConsumption($verb, $table, 1);

        $this->assertCompletionFails();

        self::assertFalse($offered);
        self::assertSame($before->getArrayCopy(), self::storedRows([self::IDENTITIES]));
        self::assertNull($this->storedRequest()->verified_at);
        self::assertNotNull($this->storedRequest()->consumed_at);
        $this->assertNoEvents();
    }

    /**
     * Rows of `[the verb, the table, the occurrence]`; a `null` verb fails the
     * commit.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: int}>
     */
    public static function provideProvisioningFailures(): iterable
    {
        yield 'at the identity, before the helper' => ['insert', self::IDENTITIES, 1];
        yield 'at the link' => ['insert', 'links.table', 1];
        yield 'at its links version' => ['update', 'connections.table', 1];
        yield 'at the membership, after the helper' => ['insert', self::IDENTITIES, 2];
        yield 'at its commit' => [null, null, 1];
    }

    /**
     * Rolls back TP, the listener's transaction; what T2 committed stays.
     *
     * @param  ?string  $verb
     * @param  ?string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideProvisioningFailures')]
    public function testProvisioningRollsBackAlone(?string $verb, ?string $table, int $occurrence): void
    {
        $this->matcher->match = LinkEmailMatch::none();

        $this->start();
        $this->startRecordingEvents();

        $before = new \ArrayObject;

        $this->onOffer(function (ResultUnlinked $event) use ($verb, $table, $occurrence, $before): void {

            $before->exchangeArray(self::storedRows([self::IDENTITIES]));

            $this->armFailure($verb, $table, $occurrence);
            $this->provisionInATransaction($event);
        });

        $this->assertCompletionFails();

        self::assertSame(1, $this->databaseFailuresFired());
        self::assertSame(0, self::storageDatabase()->transactionLevel());
        self::assertSame($before->getArrayCopy(), self::storedRows([self::IDENTITIES]));
        self::assertSame(0, Link::query()->count());
        self::assertNotNull($this->storedRequest()->verified_at);
        self::assertNotNull($this->storedRequest()->consumed_at);
        self::assertNull($this->storedRequest()->completed_at);
        $this->assertEventSequence([ResultVerified::class, ResultUnlinked::class]);
    }

    /**
     * Rows of `[the verb, the table's key]`; a `null` verb fails the commit.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideContinuationFailures(): iterable
    {
        yield 'at the code' => ['insert', 'handoff_codes.table'];
        yield 'at its flows version' => ['update', 'connections.table'];
        yield 'at completed_at' => ['update', 'authorization_requests.table'];
        yield 'at its commit' => [null, null];
    }

    /**
     * Rolls back T3; what TP and T2 committed stays.
     *
     * @param  ?string  $verb
     * @param  ?string  $table
     * @return void
     */
    #[DataProvider('provideContinuationFailures')]
    public function testTheFinalContinuationRollsBackAlone(?string $verb, ?string $table): void
    {
        $before = $this->provisionedThen(function () use ($verb, $table): void {
            $this->armFailure($verb, $table, 1);
        });

        $this->assertCompletionFails();

        self::assertSame(1, $this->databaseFailuresFired());

        $this->assertOnlyTheContinuationRolledBack($before);
    }

    /**
     * Rolls back T3 when the issuer throws; what TP committed stays.
     *
     * @param  bool  $writes
     * @return void
     */
    #[DataProvider('provideIssuers')]
    public function testAThrowingIssuerRollsBackTheFinalContinuationAlone(bool $writes): void
    {
        $issuer = $this->throwingIssuer($writes);

        $before = $this->provisionedThen(function () use ($issuer): void {
            $this->app?->instance(HandoffIssuer::class, $issuer);
        });

        $this->assertCompletionThrowsTheIssuersFailure();

        $this->assertOnlyTheContinuationRolledBack($before);
    }

    /**
     * Rows of `[the verb, the table's key]`; a `null` verb fails the commit.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideRefusalFailures(): iterable
    {
        yield 'at completed_at' => ['update', 'authorization_requests.table'];
        yield 'at its commit' => [null, null];
    }

    /**
     * Rolls back T3 of an `unlinked` ending; `ResultUnlinked` stays.
     *
     * @param  ?string  $verb
     * @param  ?string  $table
     * @return void
     */
    #[DataProvider('provideRefusalFailures')]
    public function testAFinalContinuationEndingUnlinkedRollsBackAlone(?string $verb, ?string $table): void
    {
        $this->matcher->match = LinkEmailMatch::none();

        $this->start();
        $this->startRecordingEvents();

        $before = new \ArrayObject;

        $this->onOffer(function () use ($verb, $table, $before): void {

            $before->exchangeArray(self::storedRows([self::IDENTITIES]));

            $this->armFailure($verb, $table, 1);
        });

        $this->assertCompletionFails();

        self::assertSame($before->getArrayCopy(), self::storedRows([self::IDENTITIES]));
        self::assertNull($this->storedRequest()->completed_at);
        self::assertNotNull($this->storedRequest()->verified_at);
        $this->assertEventSequence([ResultVerified::class, ResultUnlinked::class]);
        $this->assertNoFailure();
    }

    /**
     * Assert nothing of T3 stands, and everything TP and T2 committed does.
     *
     * @param  \ArrayObject<string, list<string>>  $before
     * @return void
     */
    private function assertOnlyTheContinuationRolledBack(\ArrayObject $before): void
    {
        self::assertSame(0, self::storageDatabase()->transactionLevel());
        self::assertSame($before->getArrayCopy(), self::storedRows([self::IDENTITIES]));

        $link = Link::query()->sole();

        self::assertSame(LinkState::ACTIVE, $link->state);
        self::assertSame($this->provisioned->id, $link->identity_id);
        self::assertSame(2, self::storageDatabase()->table(self::IDENTITIES)->count());
        self::assertNotNull($this->storedRequest()->verified_at);
        self::assertNotNull($this->storedRequest()->consumed_at);
        self::assertNull($this->storedRequest()->completed_at);
        $this->assertEventSequence([ResultVerified::class, ResultUnlinked::class, LinkCreated::class]);
    }

    /**
     * Assert the completion fails with the failure injected.
     *
     * @return void
     */
    private function assertCompletionFails(): void
    {
        self::assertInjectedFailure(fn (): mixed => $this->complete());
    }

    /**
     * Assert the completion fails with what the issuer threw.
     *
     * @return void
     */
    private function assertCompletionThrowsTheIssuersFailure(): void
    {
        try {
            $this->complete();

            self::fail('The completion went on.');
        } catch (\RuntimeException $exception) {
            self::assertSame(self::ISSUER_FAILURE, $exception->getMessage());
        }
    }

    /**
     * Provision and commit on the offer, then snapshot the rows before T3 runs.
     *
     * @param  \Closure(): void  $then
     * @return \ArrayObject<string, list<string>>
     */
    private function provisionedThen(\Closure $then): \ArrayObject
    {
        $this->matcher->match = LinkEmailMatch::none();

        $this->start();
        $this->startRecordingEvents();

        $before = new \ArrayObject;

        $this->onOffer(function (ResultUnlinked $event) use ($then, $before): void {

            $this->provisionInATransaction($event);

            $before->exchangeArray(self::storedRows([self::IDENTITIES]));

            $then();
        });

        return $before;
    }

    /**
     * In one storage transaction, write the identity, link it and write its
     * membership.
     *
     * @param  \SineMacula\Laravel\Sso\Events\ResultUnlinked  $event
     * @return void
     */
    private function provisionInATransaction(ResultUnlinked $event): void
    {
        self::storageDatabase()->transaction(function () use ($event): void {

            self::storageDatabase()->table(self::IDENTITIES)->insert(['kind' => 'identity']);

            self::assertTrue(app(ProvisioningHelper::class)->link($event->grant, $event->result, $this->provisioned, Clients::browser())->isCreated());

            self::storageDatabase()->table(self::IDENTITIES)->insert(['kind' => 'membership']);
        });
    }

    /**
     * Listen on the contract, so the recording listener sees the offer first.
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
     * Once T1 has committed, snapshot every row and arm the failure.
     *
     * @param  ?string  $verb
     * @param  ?string  $table
     * @param  int  $occurrence
     * @return \ArrayObject<string, list<string>>
     */
    private function armedAfterConsumption(?string $verb, ?string $table, int $occurrence): \ArrayObject
    {
        $before = new \ArrayObject;

        $this->verifying->onComplete = function () use ($verb, $table, $occurrence, $before): void {

            $before->exchangeArray(self::storedRows([self::IDENTITIES]));

            if ($occurrence === 0) {
                return;
            }

            $this->armFailure($verb, $table, $occurrence);
        };

        return $before;
    }

    /**
     * An issuer that throws, having written its code when told to.
     *
     * @param  bool  $writes
     * @return \SineMacula\Laravel\Sso\Contracts\HandoffIssuer
     */
    private function throwingIssuer(bool $writes): HandoffIssuer
    {
        $issuer = new RecordingHandoffIssuer;

        $issuer->failure = new \RuntimeException(self::ISSUER_FAILURE);

        if ($writes) {

            $store = app(DatabaseHandoffStore::class);

            $issuer->onIssue = static function (HandoffGrant $grant) use ($store): void {

                $store->issue($grant);

                self::assertSame(1, HandoffCode::query()->count());
            };
        }

        return $issuer;
    }

    /**
     * Link the subject to the identity, in this process.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @return void
     */
    private function hold(IdentityReference $identity, LinkOrigin $origin = LinkOrigin::PROVISIONING): void
    {
        self::assertTrue(
            app(LinkStore::class)->create(
                $this->connection,
                new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT),
                $identity,
                $origin,
                Clients::browser(),
            )->isCreated(),
        );
    }

    /**
     * The flow's request, read again.
     *
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function storedRequest(): AuthorizationRequest
    {
        return AuthorizationRequest::query()->sole();
    }
}
