<?php

declare(strict_types = 1);

namespace Tests\Integration\Pruning;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\DomainSettings;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Models\RateLimit;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneKind;
use SineMacula\Laravel\Sso\Pruning\Pruner;
use SineMacula\Laravel\Sso\Pruning\PruneTarget;
use SineMacula\Laravel\Sso\RateLimiting\RateLimitStore;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\MakesPrunableRows;
use Tests\Concerns\RaceFlows;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Clients;

/**
 * Races the pruner against what renews or activates a selected row. The first
 * racer holds the lock until the other is seen waiting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Pruner::class)]
#[CoversClass(PruneTarget::class)]
#[CoversClass(ReservationWithdrawal::class)]
#[CoversClass(DomainService::class)]
#[CoversClass(RateLimitStore::class)]
#[CoversClass(DatabaseSingleUseStore::class)]
final class PruningRacesTest extends LinkingTestCase
{
    use MakesPrunableRows, RaceFlows;

    /** @var string The domain of the pending claim raced for. */
    private const string PENDING = 'pending.example.org';

    /** @var string The token of the pending claim, as `makeDomain()` stores it. */
    private const string PENDING_TOKEN = 'abababababababababababababababababababababababababababababababab';

    /** @var string The single-use key raced for. */
    private const string SINGLE_USE_KEY = 'the-key-raced-for';

    /** @var string The namespace it is held in. */
    private const string SINGLE_USE_NAMESPACE = 'handoff_code';

    /** @var string What a redemption that succeeded reports. */
    private const string REDEEMED = 'redeemed';

    /** @var int How far the pruner's clock moves on past an expiry, well short of the retention. */
    private const int PAST_EXPIRY = 3600;

    /** @var int The most a counter's window holds. */
    private const int COUNTER_MAX = 10;

    /** @var string The signal the pruner raises as it sends its delete of a reservation. */
    private const string DELETING = 'deleting';

    /** @var string The signal the connection's holder raises just before it lets go. */
    private const string RELEASING = 'releasing';

    /**
     * Skip where processes cannot share the database; bind a fresh caller, an
     * open limiter and a publishing resolver.
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

        $this->allowEveryAttempt();

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(DnsResolver::class, (new FakeDnsResolver)->found('_sso-verification.' . self::PENDING, self::PENDING_TOKEN));
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
     * Rows of `[whether the caller-transaction side runs inside its own, which
     * read first]`.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideCallers(): iterable
    {
        yield 'plainly' => [false];
        yield 'inside its own transaction that read first' => [true];
    }

    /**
     * An activation holding the connection's lock stands, and the pruner
     * deletes nothing.
     *
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideCallers')]
    public function testAnActivationHoldingTheConnectionStands(bool $reads): void
    {
        [$code, $verifier] = $this->reserved();

        $row     = Link::query()->sole();
        $version = $this->linksVersion();

        $reports = $this->race([
            fn (): string => $this->holdThenCommit(fn (): string => $this->activation($code, $verifier)),
            function (): array {

                $this->awaitSignal(self::HOLDS);

                return $this->pruned(null, self::PAST_EXPIRY);
            },
        ], null, $this->snapshotsFor([$reads, false], $this->reads()));

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertFalse(self::assertRacerEnded($reports[1], false));
        self::assertSame(self::REDEEMED, $reports[0]['result']);
        self::assertSame(0, $reports[1]['result'][PruneKind::RESERVATIONS->value]);

        $link = Link::query()->sole();

        self::assertSame($row->id, $link->id);
        self::assertSame(LinkState::ACTIVE, $link->state);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $link->provenance);
        self::assertNull($link->reservation_id);
        self::assertSame($version + 1, $this->linksVersion());
    }

    /**
     * A prune holding the connection's lock refuses the activation.
     *
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideCallers')]
    public function testAPruneHoldingTheConnectionRefusesTheActivation(bool $reads): void
    {
        [$code, $verifier] = $this->reserved();

        $version = $this->linksVersion();

        $reports = $this->race([
            fn (): array => $this->pruned('links.table', self::PAST_EXPIRY),
            function () use ($code, $verifier): string {

                $this->awaitSignal(self::HOLDS);

                $outcome = $this->activation($code, $verifier);

                $this->commitSnapshot();

                return $outcome;
            },
        ], null, $this->snapshotsFor([false, $reads], $this->reads()));

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertSame(1, $reports[0]['result'][PruneKind::RESERVATIONS->value]);
        self::assertSame(0, Link::query()->count());
        self::assertSame($version + 1, $this->linksVersion());

        if (self::assertRacerEnded($reports[1], $reads)) {
            self::assertNull(HandoffCode::query()->sole()->redeemed_at);

            return;
        }

        self::assertSame('refused:reservation_invalid', $reports[1]['result']);
        self::assertNotNull(HandoffCode::query()->sole()->redeemed_at);
    }

    /**
     * The pruner locks the connection before it deletes a reservation.
     *
     * @return void
     */
    public function testAPruneWaitsOnTheConnectionBeforeItDeletes(): void
    {
        $this->reserved();

        $version = $this->linksVersion();
        $id      = $this->connection->id;

        $reports = $this->race([
            fn (): bool => self::storageDatabase()->transaction(function () use ($id): bool {

                Connection::query()->whereKey($id)->lockForUpdate()->sole();

                $this->holdUntilBlocked();

                $deleting = $this->signalled(self::DELETING);

                $this->signal(self::RELEASING);

                return $deleting;
            }),
            function (): array {

                $this->awaitSignal(self::HOLDS);

                $held = $this->watchTheDelete();

                return [$this->pruned(null, self::PAST_EXPIRY)[PruneKind::RESERVATIONS->value], $held()];
            },
        ]);

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertFalse(self::assertRacerEnded($reports[1], false));
        self::assertFalse($reports[0]['result'], 'The pruner deleted while the connection was held.');
        self::assertSame([1, false], $reports[1]['result']);
        self::assertSame(0, Link::query()->count());
        self::assertSame($version + 1, $this->linksVersion());
    }

    /**
     * An activation past its expiry is refused whichever goes first.
     *
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideCallers')]
    public function testAnActivationPastItsExpiryIsRefusedWhicheverGoesFirst(bool $reads): void
    {
        [$code, $verifier] = $this->reserved();

        $version = $this->linksVersion();

        $this->clock->advance(self::PAST_EXPIRY);

        $reports = $this->race([
            fn (): array => $this->pruned(),
            function () use ($code, $verifier): string {

                $outcome = $this->activation($code, $verifier);

                $this->commitSnapshot();

                return $outcome;
            },
        ], null, $this->snapshotsFor([false, $reads], $this->reads()));

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertSame(0, Link::query()->count());
        self::assertSame($version + 1, $this->linksVersion());

        if (self::assertRacerEnded($reports[1], $reads)) {
            self::assertSame(1, $reports[0]['result'][PruneKind::RESERVATIONS->value]);

            return;
        }

        self::assertSame('refused:handoff_expired', $reports[1]['result']);
    }

    /**
     * A renewal holding the claim stands.
     *
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideCallers')]
    public function testARenewalHoldingTheClaimStands(bool $reads): void
    {
        $claim = $this->pendingClaim($this->clock->now()->subSecond());

        $reports = $this->race([
            fn (): string => $this->holdThenCommit(fn (): string => $this->renewal()),
            function (): array {

                $this->awaitSignal(self::HOLDS);

                return $this->pruned();
            },
        ], null, $this->snapshotsFor([$reads, false], $this->reads()));

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertFalse(self::assertRacerEnded($reports[1], false));
        self::assertSame('claimed', $reports[0]['result']);
        self::assertSame(0, $reports[1]['result'][PruneKind::PENDING_CLAIMS->value]);

        $stored = $this->storedClaim();

        self::assertSame($claim->id, $stored->id);
        $this->assertRenewed($stored, $claim);
    }

    /**
     * A prune holding the claim leaves a renewal to claim afresh.
     *
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideCallers')]
    public function testAPruneHoldingTheClaimLeavesARenewalANewOne(bool $reads): void
    {
        $claim = $this->pendingClaim($this->clock->now()->subSecond());

        $reports = $this->race([
            fn (): array => $this->pruned('domains.table'),
            function (): string {

                $this->awaitSignal(self::HOLDS);

                $outcome = $this->renewal();

                $this->commitSnapshot();

                return $outcome;
            },
        ], null, $this->snapshotsFor([false, $reads], $this->reads()));

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertSame(1, $reports[0]['result'][PruneKind::PENDING_CLAIMS->value]);

        if (self::assertRacerEnded($reports[1], $reads)) {
            self::assertSame(0, Domain::query()->where('domain', self::PENDING)->count());

            return;
        }

        self::assertSame('claimed', $reports[1]['result']);

        $stored = $this->storedClaim();

        self::assertNotSame($claim->id, $stored->id);
        $this->assertRenewed($stored, $claim);
    }

    /**
     * A verification holding the claim stands.
     *
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideCallers')]
    public function testAVerificationHoldingTheClaimStands(bool $reads): void
    {
        $claim = $this->pendingClaim($this->clock->now()->addMinute());

        $reports = $this->race([
            fn (): string => $this->holdThenCommit(fn (): string => $this->verification()),
            function (): array {

                $this->awaitSignal(self::HOLDS);

                return $this->pruned(null, self::PAST_EXPIRY);
            },
        ], null, $this->snapshotsFor([$reads, false], $this->reads()));

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertFalse(self::assertRacerEnded($reports[1], false));
        self::assertSame('verified', $reports[0]['result']);
        self::assertSame(0, $reports[1]['result'][PruneKind::PENDING_CLAIMS->value]);

        $stored = $this->storedClaim();

        self::assertSame($claim->id, $stored->id);
        self::assertSame(DomainState::VERIFIED, $stored->state);
        self::assertSame(self::PENDING, $stored->verified_domain);
        self::assertNull($stored->pending_expires_at);
    }

    /**
     * A prune holding the claim refuses the verification.
     *
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideCallers')]
    public function testAPruneHoldingTheClaimRefusesTheVerification(bool $reads): void
    {
        $this->pendingClaim($this->clock->now()->addMinute());

        $reports = $this->race([
            fn (): array => $this->pruned('domains.table', self::PAST_EXPIRY),
            function (): string {

                $this->awaitSignal(self::HOLDS);

                $outcome = $this->verification();

                $this->commitSnapshot();

                return $outcome;
            },
        ], null, $this->snapshotsFor([false, $reads], $this->reads()));

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertSame(1, $reports[0]['result'][PruneKind::PENDING_CLAIMS->value]);
        self::assertSame(0, Domain::query()->where('domain', self::PENDING)->count());

        if (self::assertRacerEnded($reports[1], $reads)) {
            return;
        }

        self::assertSame('refused:domain_not_found', $reports[1]['result']);
    }

    /**
     * A counter's new window holding its row stands with a count of one.
     *
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideCallers')]
    public function testACounterRenewedWhileHeldStands(bool $reads): void
    {
        [$key, $ended] = $this->endedCounter();

        $reports = $this->race([
            fn (): int|string => $this->holdThenCommit(fn (): int|string => $this->taken($key)),
            function (): array {

                $this->awaitSignal(self::HOLDS);

                return $this->pruned();
            },
        ], null, $this->snapshotsFor([$reads, false], $this->reads()));

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertFalse(self::assertRacerEnded($reports[1], false));
        self::assertSame($this->newWindow(), $reports[0]['result']);
        self::assertSame(0, $reports[1]['result'][PruneKind::RATE_LIMITS->value]);

        $this->assertCounter($key, 1);

        app(RateLimitStore::class)->giveBack($key, $ended);

        $this->assertCounter($key, 1);

        app(RateLimitStore::class)->giveBack($key, $this->newWindow());

        $this->assertCounter($key, 0);
    }

    /**
     * A prune holding the counter leaves the next attempt a new window.
     *
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideCallers')]
    public function testAPruneHoldingTheCounterLeavesANewWindow(bool $reads): void
    {
        [$key, $ended] = $this->endedCounter();

        $reports = $this->race([
            fn (): array => $this->pruned('rate_limits.table'),
            function () use ($key): int|string {

                $this->awaitSignal(self::HOLDS);

                $window = $this->taken($key);

                $this->commitSnapshot();

                return $window;
            },
        ], null, $this->snapshotsFor([false, $reads], $this->reads()));

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertSame(1, $reports[0]['result'][PruneKind::RATE_LIMITS->value]);

        if (self::assertRacerEnded($reports[1], $reads)) {
            self::assertSame(0, RateLimit::query()->whereKey($key)->count());

            return;
        }

        self::assertSame($this->newWindow(), $reports[1]['result']);

        $this->assertCounter($key, 1);

        app(RateLimitStore::class)->giveBack($key, $ended);

        $this->assertCounter($key, 1);
    }

    /**
     * Rows of `[whether the give back holds the row first, whether it reads
     * first]`.
     *
     * @return iterable<string, array{0: bool, 1: bool}>
     */
    public static function provideGiveBacks(): iterable
    {
        yield 'the give back first, plainly' => [true, false];
        yield 'the give back first, inside its own transaction that read first' => [true, true];
        yield 'the prune first, plainly' => [false, false];
        yield 'the prune first, inside its own transaction that read first' => [false, true];
    }

    /**
     * A give back against a prune never brings the counter back.
     *
     * @param  bool  $giveBackFirst
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideGiveBacks')]
    public function testAGiveBackAgainstAPruneLeavesNoCounter(bool $giveBackFirst, bool $reads): void
    {
        [$key, $ended] = $this->endedCounter();

        $giveBack = static fn (): null => app(RateLimitStore::class)->giveBack($key, $ended);

        $reports = $this->race($giveBackFirst ? [
            fn (): null => $this->holdThenCommit($giveBack),
            function (): array {

                $this->awaitSignal(self::HOLDS);

                return $this->pruned();
            },
        ] : [
            function () use ($giveBack): null {

                $this->awaitSignal(self::HOLDS);

                $giveBack();
                $this->commitSnapshot();

                return null;
            },
            fn (): array => $this->pruned('rate_limits.table'),
        ], null, $this->snapshotsFor([$reads, false], $this->reads()));

        $giver = $reports[0];
        $prune = $reports[1];

        self::assertFalse(self::assertRacerEnded($prune, false));
        self::assertSame(1, $prune['result'][PruneKind::RATE_LIMITS->value]);

        self::assertRacerEnded($giver, $reads && !$giveBackFirst);
        self::assertSame(0, RateLimit::query()->whereKey($key)->count());
    }

    /**
     * A key replaced while held stands with exactly one holder.
     *
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideCallers')]
    public function testAKeyReplacedWhileHeldStands(bool $reads): void
    {
        $expired = $this->heldKey($this->clock->now()->subSecond());

        $reports = $this->race([
            fn (): string => $this->holdThenCommit(fn (): string => $this->recorded()),
            function (): array {

                $this->awaitSignal(self::HOLDS);

                return $this->pruned();
            },
        ], null, $this->snapshotsFor([$reads, false], $this->reads()));

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertFalse(self::assertRacerEnded($reports[1], false));
        self::assertSame(SingleUseOutcome::RECORDED->value, $reports[0]['result']);
        self::assertSame(0, $reports[1]['result'][PruneKind::SINGLE_USE_KEYS->value]);

        $this->assertOneLiveHolder($expired);
    }

    /**
     * A prune holding the key leaves it recorded once.
     *
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideCallers')]
    public function testAPruneHoldingTheKeyLeavesItRecordedOnce(bool $reads): void
    {
        $expired = $this->heldKey($this->clock->now()->subSecond());

        $reports = $this->race([
            fn (): array => $this->pruned('single_use.table'),
            function (): string {

                $this->awaitSignal(self::HOLDS);

                $outcome = $this->recorded();

                $this->commitSnapshot();

                return $outcome;
            },
        ], null, $this->snapshotsFor([false, $reads], $this->reads()));

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertSame(1, $reports[0]['result'][PruneKind::SINGLE_USE_KEYS->value]);

        if (self::assertRacerEnded($reports[1], $reads)) {
            self::assertSame(0, $this->keysHeld());

            return;
        }

        self::assertSame(SingleUseOutcome::RECORDED->value, $reports[1]['result']);

        $this->assertOneLiveHolder($expired);
    }

    /**
     * A prune between a refused insert and its delete still leaves the key
     * recorded once.
     *
     * @return void
     */
    public function testAPruneBetweenARefusedInsertAndItsDeleteStillRecords(): void
    {
        $expired = $this->heldKey($this->clock->now()->subSecond());

        $reports = $this->race([
            function (): string {

                $this->pauseBeforeDeletingTheKey();

                return $this->recorded();
            },
            function (): array {

                $this->awaitSignal('refused');

                $pruned = $this->pruned();

                $this->signal('pruned');

                return $pruned;
            },
        ]);

        self::assertFalse(self::assertRacerEnded($reports[1], false));
        self::assertSame(1, $reports[1]['result'][PruneKind::SINGLE_USE_KEYS->value]);
        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertSame(SingleUseOutcome::RECORDED->value, $reports[0]['result']);

        $this->assertOneLiveHolder($expired);
    }

    /**
     * A key still held is never released.
     *
     * @return void
     */
    public function testALiveKeyIsNeverReleased(): void
    {
        $live = $this->heldKey($this->clock->now()->addMinute());

        $reports = $this->race([
            fn (): string => $this->recorded(),
            fn (): array => $this->pruned(),
        ]);

        self::assertFalse(self::assertRacerEnded($reports[0], false));
        self::assertFalse(self::assertRacerEnded($reports[1], false));
        self::assertSame(SingleUseOutcome::SEEN->value, $reports[0]['result']);
        self::assertSame(0, $reports[1]['result'][PruneKind::SINGLE_USE_KEYS->value]);
        self::assertSame($live, SingleUseKey::query()->where('key_digest', hash('sha256', self::SINGLE_USE_KEY))->sole()->id);
    }

    /**
     * Assert the claim is pending under a new token and a later expiry.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $stored
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $was
     * @return void
     */
    private function assertRenewed(Domain $stored, Domain $was): void
    {
        self::assertSame(DomainState::PENDING, $stored->state);
        self::assertNotSame($was->verification_token, $stored->verification_token);
        self::assertSame(
            $this->clock->now()->addSeconds(app(DomainSettings::class)->pendingExpirySeconds())->getTimestamp(),
            $stored->pending_expires_at?->getTimestamp(),
        );
    }

    /**
     * Assert the counter holds its new window and the count given.
     *
     * @param  string  $key
     * @param  int  $hits
     * @return void
     */
    private function assertCounter(string $key, int $hits): void
    {
        $counter = RateLimit::query()->whereKey($key)->sole();

        self::assertSame($hits, $counter->hits);
        self::assertSame($this->newEnd(), $counter->window_ends_at->getTimestamp());
    }

    /**
     * Assert the key is held once, by a row other than the expired one, until a
     * later moment.
     *
     * @param  int  $expired
     * @return void
     */
    private function assertOneLiveHolder(int $expired): void
    {
        $holder = SingleUseKey::query()->where('namespace', self::SINGLE_USE_NAMESPACE)->where('key_digest', hash('sha256', self::SINGLE_USE_KEY))->sole();

        self::assertNotSame($expired, $holder->id);
        self::assertSame($this->keyExpiry()->getTimestamp(), $holder->expires_at->getTimestamp());
    }

    /**
     * Complete an eligible flow and answer its code and verifier.
     *
     * @return array{0: string, 1: string}
     */
    private function reserved(): array
    {
        $start      = $this->start();
        $completion = $this->complete();

        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);

        return [(string) $completion->handoff?->code->reveal(), (string) $start->verifier?->reveal()];
    }

    /**
     * Run the pruner, its clock moved on, paused before the commit after its
     * delete of the table named.
     *
     * @param  ?string  $holding
     * @param  int  $advance
     * @return array<string, int>
     *
     * @throws \SineMacula\Laravel\Sso\Pruning\PruneFailedException
     */
    private function pruned(?string $holding = null, int $advance = 0): array
    {
        $this->clock->advance($advance);

        if ($holding !== null) {
            $this->pauseBeforeCommit(self::onTable('delete', StorageConnection::table($holding)), function (): void {
                $this->holdUntilBlocked();
            });
        }

        return app(Pruner::class)->run()->deleted;
    }

    /**
     * Raise `DELETING` on the first reservation delete, answering whether the
     * holder still held it, or `null`.
     *
     * @return \Closure(): ?bool
     */
    private function watchTheDelete(): \Closure
    {
        $pattern = self::onTable('delete', StorageConnection::table('links.table'));
        $held    = null;

        self::storageDatabase()->beforeExecuting(function (string $query) use ($pattern, &$held): void {

            if ($held !== null || preg_match($pattern, strtolower($query)) !== 1) {
                return;
            }

            $held = !$this->signalled(self::RELEASING);

            $this->signal(self::DELETING);
        });

        return static function () use (&$held): ?bool {
            return $held;
        };
    }

    /**
     * Whether the named signal has been raised.
     *
     * @param  string  $name
     * @return bool
     */
    private function signalled(string $name): bool
    {
        return is_file($this->raceDirectory . '/signal-' . $name);
    }

    /**
     * Redeem the code in a transaction, a savepoint inside a snapshot.
     *
     * @param  string  $code
     * @param  string  $verifier
     * @return string
     */
    private function activation(string $code, string $verifier): string
    {
        $answer = self::storageDatabase()->transaction(
            fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $this->connection->id, $code, $verifier, Clients::browser()),
        );

        return $answer->isRedeemed() ? self::REDEEMED : 'refused:' . $answer->reason?->value;
    }

    /**
     * Claim the pending domain again.
     *
     * @return string
     */
    private function renewal(): string
    {
        $result = app(DomainService::class)->claim('tenant-1', $this->connection->id, self::PENDING, Clients::browser());

        return $result->isRefused() ? 'refused:' . $result->reason?->value : $result->status->value;
    }

    /**
     * Verify the pending domain.
     *
     * @return string
     */
    private function verification(): string
    {
        $result = app(DomainService::class)->verify('tenant-1', $this->connection->id, self::PENDING, Clients::browser());

        return $result->isRefused() ? 'refused:' . $result->reason?->value : $result->status->value;
    }

    /**
     * Take a slot of the counter's window.
     *
     * @param  string  $key
     * @return int|string
     */
    private function taken(string $key): int|string
    {
        return app(RateLimitStore::class)->take($key, self::COUNTER_MAX, $this->clock->now()->getTimestamp(), $this->newEnd());
    }

    /**
     * Record the single-use key.
     *
     * @return string
     */
    private function recorded(): string
    {
        return app(DatabaseSingleUseStore::class)->record(self::SINGLE_USE_NAMESPACE, self::SINGLE_USE_KEY, $this->keyExpiry())->value;
    }

    /**
     * Hold a record whose insert was refused just before it deletes the row in
     * the way.
     *
     * @return void
     */
    private function pauseBeforeDeletingTheKey(): void
    {
        $pattern = self::onTable('delete', StorageConnection::table('single_use.table'));
        $done    = false;

        self::storageDatabase()->beforeExecuting(function (string $query) use ($pattern, &$done): void {

            if ($done || preg_match($pattern, strtolower($query)) !== 1) {
                return;
            }

            $done = true;

            $this->signal('refused');
            $this->awaitSignal('pruned');
        });
    }

    /**
     * A pending claim of the connection expiring at the instant.
     *
     * @param  \Carbon\CarbonImmutable  $expires
     * @return \SineMacula\Laravel\Sso\Models\Domain
     */
    private function pendingClaim(CarbonImmutable $expires): Domain
    {
        return $this->makeDomain($this->connection, self::PENDING, ['pending_expires_at' => $expires]);
    }

    /**
     * The pending domain's claim, read again.
     *
     * @return \SineMacula\Laravel\Sso\Models\Domain
     */
    private function storedClaim(): Domain
    {
        return Domain::query()->where('domain', self::PENDING)->sole();
    }

    /**
     * A counter of five attempts in a window that ended a minute ago, and that
     * window as stored.
     *
     * @return array{0: string, 1: string}
     */
    private function endedCounter(): array
    {
        $ended = $this->clock->now()->subMinute();
        $key   = $this->prunableRow(PruneKind::RATE_LIMITS, $this->connection, $ended);

        RateLimit::query()->whereKey($key)->update(['hits' => 5]);

        return [$key, UtcDateTime::format(new RateLimit, $ended)];
    }

    /**
     * The Unix time a window started now ends.
     *
     * @return int
     */
    private function newEnd(): int
    {
        return $this->clock->now()->addMinute()->getTimestamp();
    }

    /**
     * That window as the table stores it.
     *
     * @return string
     */
    private function newWindow(): string
    {
        return UtcDateTime::format(new RateLimit, $this->newEnd());
    }

    /**
     * Store the single-use key until the instant, and answer its row's key.
     *
     * @param  \Carbon\CarbonImmutable  $until
     * @return int
     */
    private function heldKey(CarbonImmutable $until): int
    {
        $model = new SingleUseKey;

        return self::storageDatabase()->table($model->getTable())->insertGetId([
            'namespace'  => self::SINGLE_USE_NAMESPACE,
            'key_digest' => hash('sha256', self::SINGLE_USE_KEY),
            'expires_at' => UtcDateTime::format($model, $until),
        ]);
    }

    /**
     * How many rows hold the single-use key.
     *
     * @return int
     */
    private function keysHeld(): int
    {
        return SingleUseKey::query()->where('key_digest', hash('sha256', self::SINGLE_USE_KEY))->count();
    }

    /**
     * When a record made in a race holds the key until.
     *
     * @return \Carbon\CarbonImmutable
     */
    private function keyExpiry(): CarbonImmutable
    {
        return $this->clock->now()->addMinutes(5);
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
     * What a racer's snapshot reads.
     *
     * @return \Closure(): void
     */
    private function reads(): \Closure
    {
        return static function (): void {
            Connection::query()->get();
            Link::query()->get();
            Domain::query()->get();
            HandoffCode::query()->get();
            RateLimit::query()->get();
            SingleUseKey::query()->get();
        };
    }
}
