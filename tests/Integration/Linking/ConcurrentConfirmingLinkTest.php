<?php

declare(strict_types = 1);

namespace Tests\Integration\Linking;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\LinkConfirmed;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\Redemption\LinkBranch;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
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
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Races a `link` redemption across processes against what can change its link;
 * skipped on SQLite and without `pcntl`. A stale snapshot may fail to serialise
 * (`40001`), accepted on PostgreSQL only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkBranch::class)]
#[CoversClass(LinkStore::class)]
#[CoversClass(LinkService::class)]
#[CoversClass(ScopeWidening::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(HandoffRecheck::class)]
final class ConcurrentConfirmingLinkTest extends LinkingTestCase
{
    /** @var float Seconds a racer waits for the other's signal before it gives up. */
    private const float SIGNAL_SECONDS = 30.0;

    /** @var string What a racer reports when it failed to serialise, accepted on PostgreSQL alone. */
    private const string SERIALIZATION = 'serialization';

    /** @var string What a racer reports when it was refused for a retry of its whole transaction. */
    private const string RETRY = 'retry';

    /** @var string Directory the processes signal and report in. */
    private string $signals;

    /**
     * Bind an eligibility that lets every identity link, a fresh caller and an
     * allow-all limiter, whose counters a racer would otherwise hold locked.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
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

        $this->signals = sys_get_temp_dir() . '/link-race-' . bin2hex(random_bytes(8));

        mkdir($this->signals);
    }

    /**
     * Remove this test's signals and outcomes, and drop the tables.
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
     * A confirmation then a removal of the link: confirmed, then removed, with
     * the removal seeing what it confirmed.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testAConfirmationThenARemovalOfItsLink(bool $inTransaction): void
    {
        $link = $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);
        $flow = $this->linkFlow($this->person);

        $outcomes = $this->race($this->linkRedeemer($flow), $this->remover($link->id), $inTransaction);

        if ($this->failsToSerialize($inTransaction)) {

            self::assertSame(['redeemed|1', self::SERIALIZATION], $outcomes);
            self::assertSame(LinkOrigin::LINK_PURPOSE, Link::query()->sole()->provenance);

            return;
        }

        self::assertSame(['redeemed|1', 'removed|0'], $outcomes);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * A removal then a confirmation of the link: the confirmation finds the
     * link it observed gone, `link_changed`, and never makes it again.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testARemovalThenAConfirmationOfItsLink(bool $inTransaction): void
    {
        $link = $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);
        $flow = $this->linkFlow($this->person);

        $outcomes = $this->race($this->remover($link->id), $this->linkRedeemer($flow), $inTransaction);

        self::assertSame(0, Link::query()->count());

        if ($this->failsToSerialize($inTransaction)) {

            self::assertSame(['removed|0', self::SERIALIZATION], $outcomes);
            self::assertNull($this->storedCode($flow[0])->redeemed_at);

            return;
        }

        self::assertSame(['removed|0', 'refused:link_changed|0'], $outcomes);
        self::assertNotNull($this->storedCode($flow[0])->redeemed_at);
    }

    /**
     * Two confirmations of one link: both pass, since each proved the same
     * person, but the link is confirmed, raised and reported once.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testTwoConfirmationsOfOneLink(bool $inTransaction): void
    {
        $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);

        $first  = $this->linkFlow($this->person);
        $second = $this->linkFlow($this->person);
        $before = $this->connection->refresh()->links_version;

        $outcomes = $this->race($this->linkRedeemer($first), $this->linkRedeemer($second), $inTransaction);

        self::assertSame(
            $this->failsToSerialize($inTransaction) ? ['redeemed|1', self::SERIALIZATION] : ['redeemed|1', 'redeemed|0'],
            $outcomes,
        );
        self::assertSame(LinkOrigin::LINK_PURPOSE, Link::query()->sole()->provenance);
        self::assertSame($before + 1, $this->connection->refresh()->links_version);
    }

    /**
     * A confirmation then a suspension: the confirmed link is no longer judged
     * by scope.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testAConfirmationThenASuspensionOfItsLink(bool $inTransaction): void
    {
        [$signIn, $flow] = $this->scopeWidened();

        $outcomes = $this->race($this->linkRedeemer($flow), $this->signInRedeemer($signIn), $inTransaction);

        self::assertSame(
            $this->failsToSerialize($inTransaction) ? ['redeemed|1', self::SERIALIZATION] : ['redeemed|1', 'redeemed|0'],
            $outcomes,
        );

        $this->assertConfirmed();
    }

    /**
     * A suspension then a confirmation: the confirmation clears the suspension
     * for good.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testASuspensionThenAConfirmationOfItsLink(bool $inTransaction): void
    {
        [$signIn, $flow] = $this->scopeWidened();

        $outcomes = $this->race($this->signInRedeemer($signIn), $this->linkRedeemer($flow), $inTransaction);

        if ($this->failsToSerialize($inTransaction)) {

            self::assertSame(['refused:link_suspended|0', self::SERIALIZATION], $outcomes);

            $row = Link::query()->sole();

            self::assertSame([LinkState::SUSPENDED, LinkOrigin::VERIFIED_DOMAIN], [$row->state, $row->provenance]);
            self::assertNotNull($row->suspended_at);

            return;
        }

        self::assertSame(['refused:link_suspended|0', 'redeemed|1'], $outcomes);

        $this->assertConfirmed();
    }

    /**
     * A confirmation then a widening: the widening finds nothing to suspend.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testAConfirmationThenAWideningOfItsPerson(bool $inTransaction): void
    {
        $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);

        $flow = $this->linkFlow($this->person);

        $outcomes = $this->race($this->linkRedeemer($flow), $this->widener(), $inTransaction);

        self::assertSame(
            $this->failsToSerialize($inTransaction) ? ['redeemed|1', self::SERIALIZATION] : ['redeemed|1', 'widened:0|0'],
            $outcomes,
        );

        $this->assertConfirmed();
    }

    /**
     * A principal change widening the person's scope then a confirmation: the
     * widening latches the suspension, and the confirmation clears it for good.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testAWideningOfItsPersonThenAConfirmation(bool $inTransaction): void
    {
        $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);

        $flow = $this->linkFlow($this->person);

        $outcomes = $this->race($this->widener(), $this->linkRedeemer($flow), $inTransaction);

        if ($this->failsToSerialize($inTransaction)) {

            self::assertSame(['widened:1|0', self::SERIALIZATION], $outcomes);
            self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);

            return;
        }

        self::assertSame(['widened:1|0', 'redeemed|1'], $outcomes);

        $this->assertConfirmed();
    }

    /**
     * Two redemptions of one subject for two identities, the first the first:
     * one link, for the first; the second `subject_already_linked`.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testTwoIdentitiesLinkingOneSubjectInTurn(bool $inTransaction): void
    {
        $other  = new IdentityReference('App\Models\User', '8');
        $first  = $this->linkFlow($this->person);
        $second = $this->linkFlow($other);

        $outcomes = $this->race($this->linkRedeemer($first, $this->person), $this->linkRedeemer($second, $other), $inTransaction);

        self::assertSame(
            $this->failsToSerialize($inTransaction) ? ['redeemed|0', self::SERIALIZATION] : ['redeemed|0', 'refused:subject_already_linked|0'],
            $outcomes,
        );
        self::assertSame($this->person->id, Link::query()->sole()->identity_id);
    }

    /**
     * Two redemptions of one subject for two identities leave one link.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testTwoIdentitiesLinkingOneSubjectAtOnce(bool $inTransaction): void
    {
        $other  = new IdentityReference('App\Models\User', '8');
        $first  = $this->linkFlow($this->person);
        $second = $this->linkFlow($other);

        $outcomes = $this->race($this->linkRedeemer($first, $this->person), $this->linkRedeemer($second, $other), $inTransaction, false);
        $winner   = array_search('redeemed|0', $outcomes, true);
        $sorted   = $outcomes;

        sort($sorted);

        self::assertContains($winner, [0, 1], implode(', ', $outcomes));
        self::assertSame(
            $this->failsToSerialize($inTransaction) ? ['redeemed|0', self::SERIALIZATION] : ['redeemed|0', 'refused:subject_already_linked|0'],
            $sorted,
        );
        self::assertSame([$this->person->id, $other->id][$winner], Link::query()->sole()->identity_id);
    }

    /**
     * A link redemption then a disable of its connection: the link stands, the
     * connection is disabled, and the code stays redeemed, not voided.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testALinkRedemptionThenADisable(bool $inTransaction): void
    {
        $flow = $this->linkFlow($this->person);

        $outcomes = $this->race($this->linkRedeemer($flow), $this->disabler(), $inTransaction);

        self::assertSame(1, Link::query()->count());
        self::assertNotNull($this->storedCode($flow[0])->redeemed_at);
        self::assertNull($this->storedCode($flow[0])->voided_at);

        if ($this->failsToSerialize($inTransaction)) {

            self::assertSame(['redeemed|0', self::SERIALIZATION], $outcomes);
            self::assertTrue($this->enabled());

            return;
        }

        self::assertSame(['redeemed|0', 'disabled|0'], $outcomes);
        self::assertFalse($this->enabled());
    }

    /**
     * A disable then a link redemption: the disable voided the code, so the
     * redemption is `handoff_unknown` under the lock, and nothing is linked.
     *
     * @param  bool  $inTransaction
     * @return void
     */
    #[DataProvider('isolations')]
    public function testADisableThenALinkRedemption(bool $inTransaction): void
    {
        $flow = $this->linkFlow($this->person);

        $outcomes = $this->race($this->disabler(), $this->linkRedeemer($flow), $inTransaction);

        self::assertSame(
            $this->failsToSerialize($inTransaction) ? ['disabled|0', self::SERIALIZATION] : ['disabled|0', 'refused:handoff_unknown|0'],
            $outcomes,
        );
        self::assertSame(0, Link::query()->count());
        self::assertFalse($this->enabled());
        self::assertNotNull($this->storedCode($flow[0])->voided_at);
        self::assertNull($this->storedCode($flow[0])->redeemed_at);
    }

    /**
     * Rows of `[in a transaction, PostgreSQL outcome, MySQL outcome]`: a stale
     * snapshot fails to serialise on PostgreSQL and finds an unlocked
     * connection on MySQL.
     *
     * @return iterable<string, array{0: bool, 1: string, 2: string}>
     */
    public static function provideLinksAfterAnActivation(): iterable
    {
        $refused = 'refused:independent_authentication_required|0';

        yield 'plainly' => [false, $refused, $refused];
        yield 'inside a transaction that read first' => [true, self::SERIALIZATION, self::RETRY];
    }

    /**
     * A `link` reaching the guard an activation holds judges the new domain
     * link, refused without independent authentication.
     *
     * @param  bool  $inTransaction
     * @param  string  $onPostgres
     * @param  string  $onMysql
     * @return void
     */
    #[DataProvider('provideLinksAfterAnActivation')]
    public function testAnActivationElsewhereThenALinkRedemption(bool $inTransaction, string $onPostgres, string $onMysql): void
    {
        $signIn     = $this->flow(Purpose::SIGN_IN, null);
        $reservedIn = $this->connection->id;

        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);

        $this->connection = $this->makeConnection([
            'protocol' => VerifyingDriver::NAME,
            'enabled'  => true,
            'settings' => ['issuer' => VerifyingDriver::ISSUER],
        ]);

        $link = $this->linkFlow($this->person);

        $this->confirmation->verdict = LinkConfirmationVerdict::DEPENDENT;

        $this->stopInTheScopeUntil('acquiring');

        $activation = fn (): string => self::outcomeOf(DB::connection(StorageConnection::name())->transaction(
            fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $reservedIn, $signIn[1], $signIn[2], Clients::browser()),
        ));

        $redeemer = $this->linkRedeemer($link);
        $linking  = function () use ($redeemer): string {
            $this->signalBeforeTheGuard('acquiring');

            return $redeemer();
        };

        $outcomes = $this->race($activation, $linking, $inTransaction, false);

        self::assertSame(['redeemed|0', DB::connection()->getDriverName() === 'pgsql' ? $onPostgres : $onMysql], $outcomes);
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        self::assertSame($reservedIn, Link::query()->sole()->connection_id);
    }

    /**
     * Bind a `within_tenant` scope that marks `holding` and stops until the
     * signal exists.
     *
     * @param  string  $signal
     * @return void
     */
    private function stopInTheScopeUntil(string $signal): void
    {
        $path    = "{$this->signals}/{$signal}";
        $holding = "{$this->signals}/holding";

        $wait = static function () use ($path, $holding): void {
            touch($holding);
            self::await($path);
        };

        $this->app?->instance(PrincipalScope::class, new readonly class ($wait) implements PrincipalScope {
            /**
             * Constructor.
             *
             * @param  \Closure(): void  $wait
             */
            public function __construct(

                /** Waits for the signal, failing loudly when it never appears. */
                private \Closure $wait,
            ) {}

            /**
             * Wait for the signal, and answer `within_tenant`.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $tenantId
             * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
             */
            #[\Override]
            public function judge(IdentityReference $identity, string $tenantId): ScopeVerdict
            {
                unset($identity, $tenantId);

                ($this->wait)();

                return ScopeVerdict::WITHIN_TENANT;
            }
        });
    }

    /**
     * Touch the signal just before this process takes an identity's guard, once
     * the other holds it.
     *
     * @param  string  $signal
     * @return void
     */
    private function signalBeforeTheGuard(string $signal): void
    {
        $table   = StorageConnection::table('identity_guards.table');
        $path    = "{$this->signals}/{$signal}";
        $holding = "{$this->signals}/holding";

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query) use ($table, $path, $holding): void {

            $sql = strtolower($query);

            if (!str_starts_with($sql, 'insert') || !str_contains($sql, $table)) {
                return;
            }

            self::await($holding);
            touch($path);
        });
    }

    /**
     * A domain link with `sign_in` and `link` codes bound to it, then the
     * person's scope widened.
     *
     * @return array{0: array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: string, 2: string}, 1: array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: string, 2: string}}
     */
    private function scopeWidened(): array
    {
        $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);

        $signIn = $this->flow(Purpose::SIGN_IN, null);
        $link   = $this->linkFlow($this->person);

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        return [$signIn, $link];
    }

    /**
     * Start and complete a `link` flow for the identity, in this process,
     * before any fork.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: string, 2: string}
     */
    private function linkFlow(IdentityReference $identity): array
    {
        return $this->flow(Purpose::LINK, $identity);
    }

    /**
     * Start and complete a flow for the purpose, answering its start, its code
     * and its verifier.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: string, 2: string}
     */
    private function flow(Purpose $purpose, ?IdentityReference $identity): array
    {
        $start      = $this->start($purpose, $identity);
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());

        return [$start, (string) $completion->handoff?->code->reveal(), (string) $start->verifier?->reveal()];
    }

    /**
     * Make a link of the subject for the identity, through the store.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function hold(IdentityReference $identity, LinkOrigin $origin): Link
    {
        $creation = app(LinkStore::class)->create($this->connection, new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT), $identity, $origin, Clients::browser());

        self::assertTrue($creation->isCreated());

        return Link::query()->whereKey($creation->link?->id)->sole();
    }

    /**
     * What a process redeeming a `link` code does: redeem it as the caller, and
     * say how it ended.
     *
     * @param  array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: string, 2: string}  $flow
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return \Closure(): string
     */
    private function linkRedeemer(array $flow, ?IdentityReference $caller = null): \Closure
    {
        $caller ??= $this->person;

        return fn (): string => self::outcomeOf(
            app(HandoffRedemption::class)->redeem(Purpose::LINK, 'web', $this->connection->id, $flow[1], $flow[2], Clients::browser(), new Caller($caller)),
        );
    }

    /**
     * What a process redeeming a `sign_in` code does, which resolves the link
     * and so suspends it once the person's scope has widened.
     *
     * @param  array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: string, 2: string}  $flow
     * @return \Closure(): string
     */
    private function signInRedeemer(array $flow): \Closure
    {
        return fn (): string => self::outcomeOf(DB::connection(StorageConnection::name())->transaction(
            fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $this->connection->id, $flow[1], $flow[2], Clients::browser()),
        ));
    }

    /**
     * What a process removing the link does.
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
     * What a process disabling the connection does.
     *
     * @return \Closure(): string
     */
    private function disabler(): \Closure
    {
        return fn (): string => app(ConnectionLifecycle::class)->disable('tenant-1', $this->connection->id, Clients::browser())->status->value;
    }

    /**
     * Widen the person's scope in a transaction and report how many links were
     * suspended.
     *
     * @return \Closure(): string
     */
    private function widener(): \Closure
    {
        return fn (): string => 'widened:' . DB::connection(StorageConnection::name())->transaction(
            fn (): int => app(ScopeWidening::class)->widened([$this->person], 'tenant-2', Clients::browser()),
        );
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
        return $inTransaction && DB::connection()->getDriverName() === 'pgsql';
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
     * Whether the connection is enabled now.
     *
     * @return bool
     */
    private function enabled(): bool
    {
        return Connection::query()->whereKey($this->connection->id)->sole()->enabled;
    }

    /**
     * Assert the link stands confirmed: active, its suspension and its
     * provenance cleared.
     *
     * @return void
     */
    private function assertConfirmed(): void
    {
        $row = Link::query()->sole();

        self::assertSame([LinkState::ACTIVE, LinkOrigin::LINK_PURPOSE, null], [$row->state, $row->provenance, $row->suspended_at]);
    }

    /**
     * Fork a process per racer and collect what each reported; in turn, the
     * second starts once the first has worked.
     *
     * @param  \Closure(): string  $first
     * @param  \Closure(): string  $second
     * @param  bool  $inTransaction
     * @param  bool  $inTurn
     * @return list<string>
     */
    private function race(\Closure $first, \Closure $second, bool $inTransaction, bool $inTurn = true): array
    {
        if (DB::connection()->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        DB::disconnect();

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
     * Run the work in a forked process on its own connection, ordered by signal
     * files.
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
            DB::reconnect();
            DB::connection()->getPdo();

            $this->startRecordingEvents();

            $database = DB::connection(StorageConnection::name());

            if ($inTransaction) {
                $database->statement(self::repeatableReadStatement($database->getDriverName()));
                $database->beginTransaction();
                Connection::query()->whereKey($this->connection->id)->get();
                Link::query()->get();
                StoredCode::query()->get();
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

            $outcome .= '|' . $this->confirmationsReported();
        } catch (LinkCandidatesChanged) {
            $outcome = self::RETRY;
        } catch (\Throwable $e) {
            $outcome = self::isSerializationFailure($e) ? self::SERIALIZATION : 'error: ' . $e::class . ': ' . $e->getMessage();
        }

        file_put_contents("{$this->signals}/outcome-{$process}", $outcome);

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * How many `LinkConfirmed` this process reported.
     *
     * @return int
     */
    private function confirmationsReported(): int
    {
        return count(array_filter($this->recordedEvents(), static fn (object $event): bool => $event instanceof LinkConfirmed));
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
     * Wait for the signal for at most `SIGNAL_SECONDS`, failing loudly so a
     * serial run never passes as a race.
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
     * Whether the error chain holds PostgreSQL's serialisation failure, which
     * `DeadlockException` may wrap.
     *
     * @param  \Throwable  $exception
     * @return bool
     */
    private static function isSerializationFailure(\Throwable $exception): bool
    {
        for ($error = $exception; $error !== null; $error = $error->getPrevious()) {
            if ((string) $error->getCode() === '40001') {
                return DB::connection()->getDriverName() === 'pgsql';
            }
        }

        return false;
    }
}
