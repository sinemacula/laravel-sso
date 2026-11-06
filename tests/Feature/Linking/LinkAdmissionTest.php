<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\HandoffBinding;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RecheckLock;
use SineMacula\Laravel\Sso\Handoffs\Redemption\Admission;
use SineMacula\Laravel\Sso\Handoffs\Redemption\LinkBranch;
use SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict;
use SineMacula\Laravel\Sso\Linking\RefusingLinkEligibility;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Links\DelegatingLinkStorage;
use Tests\Fixtures\Results\ExampleResults;

/**
 * Pins how a `link` is admitted (`docs/design/linking.md`, SSO-9.9, decision
 * D5): `admit()` inside the caller's transaction, and the standalone
 * `redeem()`, which a `link` may take since it writes no session, answering
 * `isAdmitted()` false; a committed refusal spends the code and a rollback does
 * not; an exception rolls back and leaves the code to be tried again; and an
 * adapter that redeems its own codes reaches the same rules through
 * `HandoffRecheck` with a `HandoffBinding`, in the frozen order, failing closed
 * on a binding it cannot compare.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkBranch::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(Admission::class)]
#[CoversClass(RedemptionResult::class)]
final class LinkAdmissionTest extends LinkingTestCase
{
    /**
     * Bind an eligibility that lets every identity link, and a fresh caller.
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
     * A `link` code may be redeemed standalone, since it writes no session: it
     * creates the link and commits before it answers, and the result says it
     * was not admitted, so it must never lead to a session.
     *
     * @return void
     */
    public function testALinkCodeRedeemsStandaloneAndIsNotAdmitted(): void
    {
        [$start, $code, $verifier] = $this->linkFlow();

        $this->startRecordingEvents();

        $answer = app(HandoffRedemption::class)->redeem(Purpose::LINK, 'web', $this->connection->id, $code, $verifier, Clients::browser(), $this->person);

        self::assertTrue($answer->isRedeemed());
        self::assertFalse($answer->isAdmitted());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertSame($this->person->jsonSerialize(), $answer->identity?->jsonSerialize());
        self::assertSame(Link::query()->sole()->id, $answer->linkId);
        self::assertSame(LinkOrigin::LINK_PURPOSE, Link::query()->sole()->provenance);
        self::assertNotNull($this->stored($start)->redeemed_at);

        $this->assertEventSequence([LinkCreated::class, HandoffRedeemed::class]);
    }

    /**
     * `redeem()` with the caller's transaction open is what `admit()` is.
     *
     * @return void
     */
    public function testRedeemInsideTheCallersTransactionIsAdmitted(): void
    {
        [, $code, $verifier] = $this->linkFlow();

        $answer = DB::connection(StorageConnection::name())->transaction(
            fn (): RedemptionResult => app(HandoffRedemption::class)->redeem(Purpose::LINK, 'web', $this->connection->id, $code, $verifier, Clients::browser(), $this->person),
        );

        self::assertTrue($answer->isAdmitted());
    }

    /**
     * `admit()` inside the caller's transaction is admitted.
     *
     * @return void
     */
    public function testAdmitInsideTheCallersTransactionIsAdmitted(): void
    {
        [, $code, $verifier] = $this->linkFlow();

        $answer = DB::connection(StorageConnection::name())->transaction(
            fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::LINK, 'web', $this->connection->id, $code, $verifier, Clients::browser(), $this->person),
        );

        self::assertTrue($answer->isRedeemed());
        self::assertTrue($answer->isAdmitted());
    }

    /**
     * `admit()` with no transaction open is a `LogicException`, before the code
     * is touched: it can be redeemed afterwards.
     *
     * @return void
     */
    public function testAdmitWithNoTransactionOpenLeavesTheCodeUntouched(): void
    {
        [$start, $code, $verifier] = $this->linkFlow();

        try {
            app(HandoffRedemption::class)->admit(Purpose::LINK, 'web', $this->connection->id, $code, $verifier, Clients::browser(), $this->person);
            self::fail('A link was admitted with no transaction open.');
        } catch (\LogicException $exception) {
            self::assertSame('A session is admitted inside the caller\'s transaction on the package\'s storage connection (decision D5).', $exception->getMessage());
        }

        self::assertNull($this->stored($start)->redeemed_at);
        self::assertTrue(app(HandoffRedemption::class)->redeem(Purpose::LINK, 'web', $this->connection->id, $code, $verifier, Clients::browser(), $this->person)->isRedeemed());
    }

    /**
     * The standalone path needs the caller just as `admit()` does: a code and
     * its verifier alone are refused, the refusal commits, and the code is
     * spent.
     *
     * @return void
     */
    public function testTheStandalonePathStillNeedsTheCaller(): void
    {
        [$start, $code, $verifier] = $this->linkFlow();

        $this->startRecordingEvents();

        $answer = app(HandoffRedemption::class)->redeem(Purpose::LINK, 'web', $this->connection->id, $code, $verifier, Clients::browser());

        self::assertSame(FailureReason::IDENTITY_MISMATCH, $answer->reason);
        self::assertFalse($answer->isAdmitted());
        self::assertSame(0, Link::query()->count());
        self::assertNotNull($this->stored($start)->redeemed_at);

        $this->assertEventSequence([FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::REDEMPTION, FailureReason::IDENTITY_MISMATCH);
    }

    /**
     * A refusal that commits spends the code, inside the caller's transaction
     * too: a retry with everything put right is `replayed`, so the client must
     * start again.
     *
     * @return void
     */
    public function testACommittedRefusalSpendsTheCode(): void
    {
        [$start, $code, $verifier] = $this->linkFlow();

        $this->app?->instance(Freshness::class, FakeFreshness::stale());

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $this->admitted($code, $verifier)->reason);
        self::assertNotNull($this->stored($start)->redeemed_at);

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        self::assertSame(FailureReason::REPLAYED, $this->admitted($code, $verifier)->reason);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * The caller's rollback undoes the link and the consumption together, so
     * the whole transaction can be tried again, and only then is it done.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARollbackUndoesTheLinkAndTheConsumptionTogether(): void
    {
        [$start, $code, $verifier] = $this->linkFlow();

        $before = $this->connection->refresh()->links_version;

        try {
            DB::connection(StorageConnection::name())->transaction(function () use ($code, $verifier): void {

                self::assertTrue(
                    app(HandoffRedemption::class)->admit(Purpose::LINK, 'web', $this->connection->id, $code, $verifier, Clients::browser(), $this->person)->isAdmitted(),
                );
                self::assertSame(1, Link::query()->count());

                throw new \RuntimeException('The caller\'s write failed.');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('The caller\'s write failed.', $exception->getMessage());
        }

        self::assertSame(0, Link::query()->count());
        self::assertNull($this->stored($start)->redeemed_at);
        self::assertSame($before, $this->connection->refresh()->links_version);

        self::assertTrue($this->admitted($code, $verifier)->isRedeemed());
        self::assertSame(1, Link::query()->count());
    }

    /**
     * An eligibility contract that throws is a server error: it propagates,
     * rolls the redemption back with no refusal reported, and the code is not
     * spent, through the standalone path as through `admit()`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAContractExceptionRollsBackAndLeavesTheCodeUnspent(): void
    {
        [$start, $code, $verifier] = $this->linkFlow();

        $this->app?->instance(LinkEligibility::class, new readonly class implements LinkEligibility {
            /**
             * Fail.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function judge(IdentityReference $identity, SsoConnection $connection): LinkEligibilityVerdict
            {
                unset($identity, $connection);

                throw new \RuntimeException('The membership store is down.');
            }
        });

        $this->startRecordingEvents();

        try {
            app(HandoffRedemption::class)->redeem(Purpose::LINK, 'web', $this->connection->id, $code, $verifier, Clients::browser(), $this->person);
            self::fail('The contract\'s exception was swallowed.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The membership store is down.', $exception->getMessage());
        }

        $this->assertNoEvents();
        self::assertNull($this->stored($start)->redeemed_at);

        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);

        self::assertTrue($this->admitted($code, $verifier)->isRedeemed());
    }

    /**
     * An adapter that redeems its own codes links through the recheck: its
     * lock, then `admit()` with a binding of what it stored, answering the
     * whole admission; the link commits with its transaction and reports the
     * flow.
     *
     * @return void
     */
    public function testAnAdapterLinksThroughTheRecheck(): void
    {
        $result = $this->linkResult();

        $binding   = new HandoffBinding(identity: $this->person, trustVersion: 0);
        $admission = $this->underLock(
            $result,
            fn (HandoffRecheck $recheck, RecheckLock $lock): Admission => $recheck->admit($result, $binding, $lock, Clients::browser(), $this->person),
        );
        $link = Link::query()->sole();

        self::assertSame([
            'outcome'            => RecheckOutcome::PASSED,
            'identity'           => $admission->identity,
            'linkId'             => $link->id,
            'evidence'           => null,
            'linkProvenance'     => null,
            'enforcementVersion' => null,
        ], get_object_vars($admission));
        self::assertSame($this->person->jsonSerialize(), $admission->identity?->jsonSerialize());
        self::assertSame(LinkOrigin::LINK_PURPOSE, $link->provenance);
        self::assertSame($result->subject, $link->subject);
        self::assertSame($result->nameIdFormat, $link->name_id_format);

        $created = $this->recordedEvents()[0];

        self::assertInstanceOf(LinkCreated::class, $created);
        self::assertSame(ExampleResults::REFERENCE, $created->context->requestReference);
        self::assertSame('link', $created->context->purpose);
        self::assertSame('web', $created->context->application);
    }

    /**
     * `recheck()` alone judges and writes nothing, so a redeemer may ask
     * without admitting.
     *
     * @return void
     */
    public function testAnAdaptersRecheckAloneWritesNothing(): void
    {
        $result = $this->linkResult();

        $binding = new HandoffBinding(identity: $this->person, trustVersion: 0);
        $outcome = $this->underLock(
            $result,
            fn (HandoffRecheck $recheck, RecheckLock $lock): RecheckOutcome => $recheck->recheck($result, $binding, $lock, Clients::browser(), $this->person),
        );

        self::assertSame(RecheckOutcome::PASSED, $outcome);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * An adapter's binding that names no identity can never let anyone link,
     * whoever calls.
     *
     * @return void
     */
    public function testABindingNamingNoIdentityIsRefused(): void
    {
        $result = $this->linkResult();

        $binding   = new HandoffBinding(trustVersion: 0);
        $admission = $this->underLock(
            $result,
            fn (HandoffRecheck $recheck, RecheckLock $lock): Admission => $recheck->admit($result, $binding, $lock, Clients::browser(), $this->person),
        );

        self::assertSame([
            'outcome'            => RecheckOutcome::IDENTITY_MISMATCH,
            'identity'           => null,
            'linkId'             => null,
            'evidence'           => null,
            'linkProvenance'     => null,
            'enforcementVersion' => null,
        ], get_object_vars($admission));
        self::assertSame(0, Link::query()->count());
    }

    /**
     * The caller is judged first, then freshness, then eligibility, then the
     * link: a caller who is a stranger hears nothing of what else is wrong.
     *
     * @return void
     */
    public function testTheChecksRunInTheirFrozenOrder(): void
    {
        $result = $this->linkResult();

        $this->bindLinker(LinkResolution::reserved());

        $binding = new HandoffBinding(identity: $this->person, trustVersion: 0);
        $outcome = fn (?IdentityReference $caller): RecheckOutcome => $this->underLock(
            $result,
            static fn (HandoffRecheck $recheck, RecheckLock $lock): RecheckOutcome => $recheck->recheck($result, $binding, $lock, Clients::browser(), $caller),
        );

        $stale = FakeFreshness::stale();

        $this->app?->instance(Freshness::class, $stale);
        $this->app?->instance(LinkEligibility::class, new RefusingLinkEligibility);

        self::assertSame(RecheckOutcome::IDENTITY_MISMATCH, $outcome(new IdentityReference('App\Models\User', '8')));
        self::assertSame([], $stale->asked());
        self::assertSame(RecheckOutcome::FRESHNESS_REQUIRED, $outcome($this->person));

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        self::assertSame(RecheckOutcome::LINK_INELIGIBLE, $outcome($this->person));

        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);

        self::assertSame(RecheckOutcome::LINK_RESERVED, $outcome($this->person));
    }

    /**
     * What the link is now and what the binding says was observed, and what a
     * `link` makes of it: the bound identity is `App\Models\User` `7`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Links\LinkResolution, 1: ?string, 2: bool, 3: \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome}>
     */
    public static function continuities(): iterable
    {
        $bound   = new IdentityReference('App\Models\User', '7');
        $other   = new IdentityReference('App\Models\User', '8');
        $cased   = new IdentityReference('app\models\user', '7');
        $absent  = LinkResolution::absent();
        $held    = LinkResolution::linked($bound, 'link-7');
        $paused  = LinkResolution::suspended($bound, 'link-7');
        $replace = LinkResolution::linked($bound, 'link-9');

        yield 'absent, none observed: created' => [$absent, null, false, RecheckOutcome::PASSED];
        yield 'absent, one observed: removed' => [$absent, 'link-7', false, RecheckOutcome::LINK_CHANGED];
        yield 'absent, an identity observed with no link: closed' => [$absent, null, true, RecheckOutcome::LINK_CHANGED];
        yield 'held, none observed: idempotent' => [$held, null, false, RecheckOutcome::PASSED];
        yield 'held, the same observed' => [$held, 'link-7', true, RecheckOutcome::PASSED];
        yield 'held, the same observed while suspended at completion' => [$held, 'link-7', false, RecheckOutcome::PASSED];
        yield 'held, another observed: replaced' => [$replace, 'link-7', true, RecheckOutcome::LINK_CHANGED];
        yield 'held, an identity observed with no link: closed' => [$held, null, true, RecheckOutcome::LINK_CHANGED];
        yield 'suspended, none observed' => [$paused, null, false, RecheckOutcome::PASSED];
        yield 'suspended, the same observed' => [$paused, 'link-7', false, RecheckOutcome::PASSED];
        yield 'suspended, another observed: replaced' => [LinkResolution::suspended($bound, 'link-9'), 'link-7', false, RecheckOutcome::LINK_CHANGED];
        yield 'reserved, none observed' => [LinkResolution::reserved(), null, false, RecheckOutcome::LINK_RESERVED];
        yield 'reserved, one observed' => [LinkResolution::reserved(), 'link-7', true, RecheckOutcome::LINK_RESERVED];
        yield 'another holds it, none observed' => [LinkResolution::linked($other, 'link-8'), null, false, RecheckOutcome::SUBJECT_ALREADY_LINKED];
        yield 'another holds it, the same observed' => [LinkResolution::linked($other, 'link-7'), 'link-7', true, RecheckOutcome::SUBJECT_ALREADY_LINKED];
        yield 'another has it suspended' => [LinkResolution::suspended($other, 'link-8'), null, false, RecheckOutcome::SUBJECT_ALREADY_LINKED];
        yield 'a holder differing only by case' => [LinkResolution::linked($cased, 'link-7'), 'link-7', true, RecheckOutcome::SUBJECT_ALREADY_LINKED];
        yield 'its scope unknown' => [LinkResolution::scopeUnknown($bound, 'link-7'), 'link-7', true, RecheckOutcome::PRINCIPAL_SCOPE_UNKNOWN];
        yield 'another holds it, its scope unknown' => [LinkResolution::scopeUnknown($other, 'link-8'), null, false, RecheckOutcome::SUBJECT_ALREADY_LINKED];
    }

    /**
     * Each state of the link against what was observed comes to exactly its own
     * outcome.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  $now
     * @param  ?string  $observed
     * @param  bool  $linkedAtCompletion
     * @param  \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome  $expected
     * @return void
     */
    #[DataProvider('continuities')]
    public function testEachLinkStateComesToItsOutcome(LinkResolution $now, ?string $observed, bool $linkedAtCompletion, RecheckOutcome $expected): void
    {
        $result  = $this->linkResult();
        $binding = new HandoffBinding($linkedAtCompletion ? $this->person : null, $observed, $this->person, trustVersion: 0);

        $this->bindLinker($now);

        $outcome = $this->underLock(
            $result,
            fn (HandoffRecheck $recheck, RecheckLock $lock): RecheckOutcome => $recheck->recheck($result, $binding, $lock, Clients::browser(), $this->person),
        );

        self::assertSame($expected, $outcome);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * A link as `judge()` read it, the link as `admit()` read it after, and
     * what the admission comes to, with nothing written: a linker that does not
     * hold the redemption's locks can never make it write what was not judged.
     *
     * @return iterable<string, array{
     *     0: \SineMacula\Laravel\Sso\Links\LinkResolution,
     *     1: \SineMacula\Laravel\Sso\Links\LinkResolution,
     *     2: ?string,
     *     3: \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome,
     * }>
     */
    public static function movedLinks(): iterable
    {
        $bound = new IdentityReference('App\Models\User', '7');
        $other = new IdentityReference('App\Models\User', '8');

        yield 'reserved since' => [LinkResolution::absent(), LinkResolution::reserved(), null, RecheckOutcome::LINK_RESERVED];
        yield 'taken since' => [LinkResolution::absent(), LinkResolution::linked($other, 'link-8'), null, RecheckOutcome::SUBJECT_ALREADY_LINKED];
        yield 'removed since' => [LinkResolution::linked($bound, 'link-7'), LinkResolution::absent(), 'link-7', RecheckOutcome::LINK_CHANGED];
        yield 'replaced since' => [LinkResolution::linked($bound, 'link-7'), LinkResolution::linked($bound, 'link-9'), 'link-7', RecheckOutcome::LINK_CHANGED];
    }

    /**
     * What `admit()` reads is judged again: a linker whose answer moved since
     * `judge()` comes to a refusal, with nothing written.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  $judged
     * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  $admitted
     * @param  ?string  $observed
     * @param  \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome  $expected
     * @return void
     */
    #[DataProvider('movedLinks')]
    public function testALinkThatMovedBeforeTheAdmissionWritesNothing(LinkResolution $judged, LinkResolution $admitted, ?string $observed, RecheckOutcome $expected): void
    {
        $result = $this->linkResult();

        $this->bindLinker($judged, $admitted);

        $binding   = new HandoffBinding(linkId: $observed, identity: $this->person, trustVersion: 0);
        $admission = $this->underLock(
            $result,
            fn (HandoffRecheck $recheck, RecheckLock $lock): Admission => $recheck->admit($result, $binding, $lock, Clients::browser(), $this->person),
        );

        $refused = ['outcome' => $expected, 'identity' => null, 'linkId' => null, 'evidence' => null, 'linkProvenance' => null, 'enforcementVersion' => null];

        self::assertSame($refused, get_object_vars($admission));
        self::assertSame(0, Link::query()->count());
    }

    /**
     * An adapter's confirmation answers the link it confirmed, its id exactly.
     *
     * @return void
     */
    public function testAnAdapterConfirmsTheLinkItsBindingObserved(): void
    {
        $result = $this->linkResult();
        $link   = app(LinkStore::class)->create($this->connection, LinkSubject::of($result), $this->person, LinkOrigin::VERIFIED_DOMAIN, Clients::browser())->link;

        self::assertNotNull($link);

        $binding   = new HandoffBinding($this->person, $link->id, $this->person, trustVersion: 0);
        $admission = $this->underLock(
            $result,
            fn (HandoffRecheck $recheck, RecheckLock $lock): Admission => $recheck->admit($result, $binding, $lock, Clients::browser(), $this->person),
        );

        self::assertSame([
            'outcome'            => RecheckOutcome::PASSED,
            'identity'           => $admission->identity,
            'linkId'             => $link->id,
            'evidence'           => null,
            'linkProvenance'     => null,
            'enforcementVersion' => null,
        ], get_object_vars($admission));
        self::assertSame(LinkOrigin::LINK_PURPOSE, Link::query()->sole()->provenance);
    }

    /**
     * A `link` never completes a sign-in: acknowledging one for its result is a
     * `LogicException`.
     *
     * @return void
     */
    public function testALinkResultAcknowledgesNoSignIn(): void
    {
        $result = $this->linkResult();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Only a [sign_in] result completes a sign-in, not a [link] one.');

        $this->underLock($result, static function (HandoffRecheck $recheck, RecheckLock $lock) use ($result): void {
            $recheck->acknowledgeSignIn($result, $lock);
        });
    }

    /**
     * A recheck outside the redeemer's transaction is a `LogicException`.
     *
     * @return void
     */
    public function testTheRecheckNeedsTheRedeemersTransaction(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A handoff is rechecked inside the redeemer\'s transaction on the package\'s storage connection (decision D5).');

        app(HandoffRecheck::class)->lock('tenant-1', $this->connection->id, 'web');
    }

    /**
     * An adapter's lock that does not name the identity of a `link` never takes
     * its guard, so the redemption refuses to judge under it, whoever calls.
     *
     * @return void
     */
    public function testTheRecheckNeedsTheGuardOfTheIdentity(): void
    {
        $result = $this->linkResult();

        $this->expectExceptionObject(new \LogicException('A [link] redemption locks with the identity it was started for: pass it to HandoffRecheck::lock().'));

        DB::connection(StorageConnection::name())->transaction(function () use ($result): void {

            $recheck = app(HandoffRecheck::class);

            $recheck->recheck(
                $result,
                new HandoffBinding(identity: $this->person, trustVersion: 0),
                $recheck->lock('tenant-1', $this->connection->id, 'web'),
                Clients::browser(),
                $this->person,
            );
        });
    }

    /**
     * A lock taken for another application cannot be used for the result.
     *
     * @return void
     */
    public function testTheRecheckNeedsTheLockOfItsResult(): void
    {
        $result = $this->linkResult();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A handoff is rechecked under the lock taken for its result\'s tenant, connection and application.');

        DB::connection(StorageConnection::name())->transaction(function () use ($result): void {

            $recheck = app(HandoffRecheck::class);

            $recheck->recheck(
                $result,
                new HandoffBinding(identity: $this->person, trustVersion: 0),
                $recheck->lock('tenant-1', $this->connection->id, 'mobile'),
                Clients::browser(),
                $this->person,
            );
        });
    }

    /**
     * The branch is reached only for a flow naming its identity; called
     * directly for a binding naming none, it refuses to write.
     *
     * @return void
     */
    public function testTheBranchWritesNothingForABindingNamingNoIdentity(): void
    {
        $result  = $this->linkResult();
        $lock    = RecheckLock::held('tenant-1', $this->connection->id, 'web', $this->connection, null);
        $context = new RedemptionContext($result, new HandoffBinding(trustVersion: 0), $lock, $this->connection, Clients::browser(), $this->person);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A link flow names the identity it was started for.');

        app(LinkBranch::class)->admit($context);
    }

    /**
     * Start and complete a `link` flow, answering its start, its code and its
     * verifier.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: string, 2: string}
     */
    private function linkFlow(): array
    {
        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());

        return [$start, (string) $completion->handoff?->code->reveal(), (string) $start->verifier?->reveal()];
    }

    /**
     * Redeem the code as the bound caller inside the caller's transaction.
     *
     * @param  string  $code
     * @param  string  $verifier
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function admitted(string $code, string $verifier): RedemptionResult
    {
        return DB::connection(StorageConnection::name())->transaction(
            fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::LINK, 'web', $this->connection->id, $code, $verifier, Clients::browser(), $this->person),
        );
    }

    /**
     * The stored code of the flow.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return \SineMacula\Laravel\Sso\Models\HandoffCode
     */
    private function stored(StartResult $start): StoredCode
    {
        return StoredCode::query()->where('request_reference', $start->reference?->value)->sole();
    }

    /**
     * A verified `link` result through the connection, as an adapter restores
     * one from its own code.
     *
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private function linkResult(): VerifiedResult
    {
        return ExampleResults::full(Purpose::LINK, $this->connection->id);
    }

    /**
     * Run what is given as an adapter does, inside its transaction with the
     * recheck's lock taken first, for the result.
     *
     * @template TAnswer
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \Closure(\SineMacula\Laravel\Sso\Handoffs\HandoffRecheck, \SineMacula\Laravel\Sso\Handoffs\RecheckLock): TAnswer  $work
     * @return TAnswer
     */
    private function underLock(VerifiedResult $result, \Closure $work): mixed
    {
        return DB::connection(StorageConnection::name())->transaction(function () use ($result, $work): mixed {

            $recheck = app(HandoffRecheck::class);

            return $work($recheck, $recheck->lock($result->tenantId, $result->connectionId, $result->application, null, $this->person));
        });
    }

    /**
     * Bind a linker answering each resolution in turn, the last for ever after.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  ...$answers
     * @return void
     */
    private function bindLinker(LinkResolution ...$answers): void
    {
        $this->app?->instance(Linker::class, new DelegatingLinkStorage(app(LinkStore::class), ...$answers));
    }
}
