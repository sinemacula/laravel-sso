<?php

declare(strict_types = 1);

namespace Tests\Integration\Combined;

use Illuminate\Database\Connection as DatabaseConnection;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\IdentityGuard;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RaceFlows;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Clients;

/**
 * Integration tests racing a reservation against provisioning the same subject.
 *
 * Orders are forced by lock waits, never timing. Skipped on SQLite and without
 * `pcntl`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(ProvisioningHelper::class)]
#[CoversClass(LinkReservations::class)]
#[CoversClass(LinkStore::class)]
final class ReservationProvisioningRacesTest extends LinkingTestCase
{
    use RaceFlows;

    /** @var string The signal the provisioning flow raises once its result is offered. */
    private const string OFFERED = 'offered';

    /** @var string The signal the reserving flow raises once its plain reads are done. */
    private const string DISCOVERED = 'discovered';

    /** @var string The signal the provisioning flow raises once its link has committed. */
    private const string PROVISIONED = 'provisioned';

    /** @var string What a completion that ran every step reports. */
    private const string COMPLETED = 'completed:-';

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The new identity the listener provisions. */
    private IdentityReference $provisioned;

    /**
     * Skip where processes cannot share the database, and bind a fresh caller
     * and an open limiter.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpRace();

        $this->provisioned = new IdentityReference('App\Models\User', 'provisioned');

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->allowEveryAttempt();
    }

    /**
     * Remove what the race used.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->tearDownRace();

        parent::tearDown();
    }

    /**
     * Rows of `[whether the listener's transaction read first]`.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideListeners(): iterable
    {
        yield 'plainly' => [false];
        yield 'in the listener\'s transaction, which read first' => [true];
    }

    /**
     * With the reservation holding T2, the helper makes nothing.
     *
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideListeners')]
    public function testAReservationHoldingTheConnectionThenTheHelper(bool $reads): void
    {
        [$reservingState, $reservingStart] = $this->startedFlow();
        [$provisioningState]               = $this->startedFlow();

        $reports = $this->race([
            function () use ($reservingState): array {

                $this->awaitSignal(self::OFFERED);

                $this->pauseBeforeCommit(self::onTable('insert', StorageConnection::table('links.table')), function (): void {
                    $this->holdUntilBlocked();
                });

                return $this->reservation($reservingState);
            },
            fn (): array => $this->provisioning($provisioningState, $reads, function (ResultUnlinked $event): string {

                $this->awaitSignal(self::HOLDS);

                return $this->helped($event);
            }),
        ]);

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertSame(self::COMPLETED, $reports[0]['result']['completion'] ?? null);

        $held = Link::query()->sole();

        self::assertSame(LinkState::RESERVED, $held->state);
        self::assertSame($this->person->id, $held->identity_id);
        self::assertSame(1, $this->linksVersion());

        if (!self::assertRacerEnded($reports[1], $reads)) {
            self::assertSame('subject_already_linked', $reports[1]['result']['helper'] ?? null);
            self::assertSame('failed:link_reserved', $reports[1]['result']['completion'] ?? null);
        }

        $redeemed = $this->redeemed($reports[0], $reservingStart);

        self::assertTrue($redeemed->isRedeemed());
        self::assertSame($this->person->id, $redeemed->linkedIdentity?->id);

        $link = Link::query()->sole();

        self::assertSame($held->id, $link->id);
        self::assertSame(LinkState::ACTIVE, $link->state);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $link->provenance);
    }

    /**
     * With the helper holding TP, the other completion finds the link and
     * reserves nothing.
     *
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideListeners')]
    public function testTheHelperHoldingTheConnectionThenAReservation(bool $reads): void
    {
        [$reservingState, $reservingStart] = $this->startedFlow();
        [$provisioningState]               = $this->startedFlow();

        $reports = $this->race([
            function () use ($reservingState): array {

                $this->awaitSignal(self::HOLDS);

                return $this->reservation($reservingState);
            },
            fn (): array => $this->provisioning(
                $provisioningState,
                $reads,
                fn (ResultUnlinked $event): string => self::storageDatabase()->transaction(function () use ($event): string {

                    $helped = $this->helped($event);

                    $this->holdUntilBlocked();

                    return $helped;
                }),
            ),
        ]);

        $this->assertTheProvisionedIdentityHoldsTheSubject($reports, $reservingStart);
    }

    /**
     * A reserving flow that read before TP committed finds the link under its
     * locks.
     *
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideListeners')]
    public function testTheHelperCommittingBetweenAPlainReadAndTheLocks(bool $reads): void
    {
        [$reservingState, $reservingStart] = $this->startedFlow();
        [$provisioningState]               = $this->startedFlow();

        $reports = $this->race([
            function () use ($reservingState): array {

                $this->awaitSignal(self::OFFERED);
                $this->pauseBeforeSecondTransaction();

                return $this->reservation($reservingState);
            },
            fn (): array => $this->provisioning(
                $provisioningState,
                $reads,
                function (ResultUnlinked $event): string {

                    $this->awaitSignal(self::DISCOVERED);

                    return $this->helped($event);
                },
                function (): void {
                    $this->signal(self::PROVISIONED);
                },
            ),
        ]);

        $this->assertTheProvisionedIdentityHoldsTheSubject($reports, $reservingStart);

        self::assertNull(IdentityGuard::query()->sole()->domain_linked_at);
    }

    /**
     * Assert the helper made the one link and the other flow reserved nothing.
     *
     * @param  list<array{result: mixed, error: ?string}>  $reports
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return void
     */
    private function assertTheProvisionedIdentityHoldsTheSubject(array $reports, StartResult $start): void
    {
        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertFalse(self::assertRacerEnded($reports[1], false));
        self::assertSame(self::COMPLETED, $reports[0]['result']['completion'] ?? null);
        self::assertSame('created', $reports[1]['result']['helper'] ?? null);
        self::assertSame(self::COMPLETED, $reports[1]['result']['completion'] ?? null);

        $link = Link::query()->sole();

        self::assertSame(LinkState::ACTIVE, $link->state);
        self::assertSame(LinkOrigin::PROVISIONING, $link->provenance);
        self::assertSame($this->provisioned->id, $link->identity_id);
        self::assertNull($link->reservation_id);
        self::assertSame(1, $this->linksVersion());

        $redeemed = $this->redeemed($reports[0], $start);

        self::assertSame($this->provisioned->id, $redeemed->linkedIdentity?->id);
        self::assertSame($link->id, $redeemed->linkId);
        self::assertSame($link->id, Link::query()->sole()->id);
    }

    /**
     * In a forked process: complete the flow whose email matches the person.
     *
     * @param  string  $state
     * @return array{completion: string, code: ?string}
     */
    private function reservation(string $state): array
    {
        $completion = $this->completion($state);

        return ['completion' => self::outcomeOf($completion), 'code' => $completion->handoff?->code->reveal()];
    }

    /**
     * In a forked process: complete the unmatched flow, provisioning from a
     * listener.
     *
     * @param  string  $state
     * @param  bool  $reads
     * @param  \Closure(\SineMacula\Laravel\Sso\Events\ResultUnlinked): string  $link
     * @param  ?\Closure(): void  $after
     * @return array{helper: ?string, completion: string}
     */
    private function provisioning(string $state, bool $reads, \Closure $link, ?\Closure $after = null): array
    {
        $this->matcher->match = LinkEmailMatch::none();

        $helper = null;

        Event::listen(ResultUnlinked::class, function (ResultUnlinked $event) use ($reads, $link, $after, &$helper): void {

            if ($reads) {
                $this->openSnapshot($this->reads());
            }

            $this->signal(self::OFFERED);

            $helper = $link($event);

            $this->endListenersTransaction($helper === 'created');

            if ($after === null) {
                return;
            }

            $after();
        });

        $completion = self::outcomeOf($this->completion($state));

        return ['helper' => $helper, 'completion' => $completion];
    }

    /**
     * Commit the listener's transaction if the helper linked, else roll back.
     *
     * @param  bool  $linked
     * @return void
     */
    private function endListenersTransaction(bool $linked): void
    {
        $database = self::storageDatabase();

        if ($database->transactionLevel() === 0) {
            return;
        }

        $linked ? $database->commit() : $database->rollBack();
    }

    /**
     * Link the offered result to the provisioned identity and say how it ended.
     *
     * @param  \SineMacula\Laravel\Sso\Events\ResultUnlinked  $event
     * @return string
     */
    private function helped(ResultUnlinked $event): string
    {
        return app(ProvisioningHelper::class)->link($event->grant, $event->result, $this->provisioned, Clients::browser())->status->value;
    }

    /**
     * Hold the completion just before T2 until the helper's link has committed.
     *
     * @return void
     */
    private function pauseBeforeSecondTransaction(): void
    {
        $opened = 0;

        self::storageDatabase()->beforeStartingTransaction(function (DatabaseConnection $connection) use (&$opened): void {

            if ($connection->transactionLevel() > 0 || ++$opened !== 2) {
                return;
            }

            $this->signal(self::DISCOVERED);
            $this->awaitSignal(self::PROVISIONED);
        });
    }

    /**
     * What the listener's transaction reads first.
     *
     * @return \Closure(): void
     */
    private function reads(): \Closure
    {
        return function (): void {
            Connection::query()->whereKey($this->connection->id)->get();
            AuthorizationRequest::query()->where('connection_id', $this->connection->id)->get();
            Link::query()->where('connection_id', $this->connection->id)->get();
        };
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
     * Redeem the racer's code once the race has ended.
     *
     * @param  array{result: mixed, error: ?string}  $report
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function redeemed(array $report, StartResult $start): RedemptionResult
    {
        $code     = $report['result']['code'] ?? null;
        $verifier = (string) $start->verifier?->reveal();

        self::assertIsString($code);

        return self::storageDatabase()->transaction(
            fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $this->connection->id, $code, $verifier, Clients::browser()),
        );
    }

    /**
     * The connection's links version, read again.
     *
     * @return int
     */
    private function linksVersion(): int
    {
        return Connection::query()->whereKey($this->connection->id)->sole()->links_version;
    }

    /**
     * How the completion ended.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @return string
     */
    private static function outcomeOf(CompletionResult $result): string
    {
        return sprintf('%s:%s', $result->status->value, $result->reason->value ?? '-');
    }
}
