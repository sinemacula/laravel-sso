<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\HandoffBinding;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\Redemption\Admission;
use SineMacula\Laravel\Sso\Handoffs\Redemption\SignInBranch;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\ReservationActivation;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\Fixtures\Results\ExampleResults;

/**
 * Adversarial tests of a `sign_in`'s continuity at redemption.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInBranch::class)]
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(ReservationActivation::class)]
final class SignInBranchTest extends LinkingTestCase
{
    /** @var int How many times the evidence contract was asked. */
    private int $asked = 0;

    /**
     * Bind an evidence contract that counts each time it is asked and accepts
     * nothing.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindEvidence(null);
    }

    /**
     * Rows of the link now, what the code was bound to and the outcome; the
     * bound identity is `App\Models\User` `7`, by link `link-7`.
     *
     * @return iterable<string, array<int, mixed>>
     */
    public static function continuities(): iterable
    {
        $bound = new IdentityReference('App\Models\User', '7');
        $other = new IdentityReference('App\Models\User', '8');
        $cased = new IdentityReference('app\models\user', '7');

        yield 'still absent, an unlinked handoff' => [LinkResolution::absent(), null, null, RecheckOutcome::PASSED];
        yield 'absent, the link removed' => [LinkResolution::absent(), $bound, 'link-7', RecheckOutcome::LINK_CHANGED];
        yield 'absent, a link observed for no identity' => [LinkResolution::absent(), null, 'link-7', RecheckOutcome::LINK_CHANGED];
        yield 'absent, an identity observed with no link' => [LinkResolution::absent(), $bound, null, RecheckOutcome::LINK_CHANGED];
        yield 'the same link, the same identity' => [LinkResolution::linked($bound, 'link-7'), $bound, 'link-7', RecheckOutcome::PASSED];
        yield 'the link made again, the same identity' => [LinkResolution::linked($bound, 'link-9'), $bound, 'link-7', RecheckOutcome::LINK_CHANGED];
        yield 'the same link, another identity' => [LinkResolution::linked($other, 'link-7'), $bound, 'link-7', RecheckOutcome::LINK_CHANGED];
        yield 'another link, another identity' => [LinkResolution::linked($other, 'link-8'), $bound, 'link-7', RecheckOutcome::LINK_CHANGED];
        yield 'the same link, an identity differing by case' => [LinkResolution::linked($cased, 'link-7'), $bound, 'link-7', RecheckOutcome::LINK_CHANGED];
        yield 'linked, an identity observed with no link' => [LinkResolution::linked($bound, 'link-7'), $bound, null, RecheckOutcome::LINK_CHANGED];
        yield 'an unlinked handoff gained a link' => [LinkResolution::linked($bound, 'link-7'), null, null, RecheckOutcome::LINK_CHANGED];
        yield 'an unlinked handoff gained another\'s link' => [LinkResolution::linked($other, 'link-8'), null, null, RecheckOutcome::LINK_CHANGED];
        yield 'suspended, the same link' => [LinkResolution::suspended($bound, 'link-7'), $bound, 'link-7', RecheckOutcome::LINK_SUSPENDED];
        yield 'suspended, another link' => [LinkResolution::suspended($bound, 'link-9'), $bound, 'link-7', RecheckOutcome::LINK_SUSPENDED];
        yield 'suspended, another identity' => [LinkResolution::suspended($other, 'link-8'), $bound, 'link-7', RecheckOutcome::LINK_SUSPENDED];
        yield 'suspended, an unlinked handoff' => [LinkResolution::suspended($bound, 'link-7'), null, null, RecheckOutcome::LINK_SUSPENDED];
        yield 'reserved, a link observed' => [LinkResolution::reserved(), $bound, 'link-7', RecheckOutcome::LINK_CHANGED];
        yield 'reserved, an unlinked handoff' => [LinkResolution::reserved(), null, null, RecheckOutcome::LINK_CHANGED];
    }

    /**
     * Every link state against every binding.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  $now
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $linkId
     * @param  \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome  $expected
     * @return void
     */
    #[DataProvider('continuities')]
    public function testEachLinkStateComesToItsOutcome(LinkResolution $now, ?IdentityReference $identity, ?string $linkId, RecheckOutcome $expected): void
    {
        $this->bindLinker($now);

        $result  = ExampleResults::full(Purpose::SIGN_IN, $this->connection->id);
        $outcome = DB::connection(StorageConnection::name())->transaction(static function () use ($result, $identity, $linkId): RecheckOutcome {

            $recheck = app(HandoffRecheck::class);
            $lock    = $recheck->lock($result->tenantId, $result->connectionId, $result->application);

            return $recheck->recheck($result, new HandoffBinding($identity, $linkId, trustVersion: 0), $lock, Clients::browser());
        });

        self::assertSame($expected, $outcome);
        self::assertSame(0, $this->asked);
    }

    /**
     * What an admission answers when a link holds: that identity and link, and
     * the evidence, asked once.
     *
     * @return void
     */
    public function testAnAdmissionOfALinkAsksOnceAndAnswersIt(): void
    {
        $accepted = new AcceptedEvidence($this->connection->id, $this->clock->now(), ['pwd']);

        $this->bindEvidence($accepted);
        $this->bindLinker(LinkResolution::linked($this->person, 'link-7'));

        $admission = $this->admitted(new HandoffBinding($this->person, 'link-7', trustVersion: 0));

        self::assertSame(RecheckOutcome::PASSED, $admission->outcome);
        self::assertSame($this->person, $admission->identity);
        self::assertSame('link-7', $admission->linkId);
        self::assertSame($accepted, $admission->evidence);
        self::assertSame(1, $this->asked);
    }

    /**
     * An admission of an unlinked handoff establishes nobody, so it asks
     * nothing, whatever the contract would answer.
     *
     * @return void
     */
    public function testAnAdmissionOfAnUnlinkedHandoffAsksNothing(): void
    {
        $this->bindEvidence(new AcceptedEvidence($this->connection->id, $this->clock->now(), ['pwd']));
        $this->bindLinker(LinkResolution::absent());

        $admission = $this->admitted(new HandoffBinding(trustVersion: 0));

        self::assertSame(RecheckOutcome::PASSED, $admission->outcome);
        self::assertNull($admission->identity);
        self::assertNull($admission->linkId);
        self::assertNull($admission->evidence);
        self::assertSame(0, $this->asked);
    }

    /**
     * An admission refused asks nothing.
     *
     * @return void
     */
    public function testAnAdmissionRefusedAsksNothing(): void
    {
        $this->bindEvidence(new AcceptedEvidence($this->connection->id, $this->clock->now(), ['pwd']));
        $this->bindLinker(LinkResolution::absent());

        $admission = $this->admitted(new HandoffBinding($this->person, 'link-7', trustVersion: 0));

        self::assertSame(RecheckOutcome::LINK_CHANGED, $admission->outcome);
        self::assertNull($admission->evidence);
        self::assertSame(0, $this->asked);
    }

    /**
     * The same link, untouched, redeems: its identity and id are answered.
     *
     * @return void
     */
    public function testTheSameLinkRedeems(): void
    {
        $this->linkTheSubject();

        $start  = $this->start();
        $answer = $this->admit($this->complete(), $start);

        self::assertTrue($answer->isAdmitted());
        self::assertSame($this->person->id, $answer->linkedIdentity?->id);
        self::assertSame(Link::query()->sole()->id, $answer->linkId);
        self::assertSame(1, $this->asked);
    }

    /**
     * A link deleted and made again for the same person is `link_changed`, by
     * its id.
     *
     * @return void
     */
    public function testALinkDeletedAndMadeAgainIsChanged(): void
    {
        $this->linkTheSubject();

        $start      = $this->start();
        $completion = $this->complete();
        $before     = Link::query()->sole()->id;

        Link::query()->delete();

        $this->linkTheSubject();

        self::assertNotSame($before, Link::query()->sole()->id);

        $this->assertRefused($completion, $start, FailureReason::LINK_CHANGED);
    }

    /**
     * A link removed since completion is changed.
     *
     * @return void
     */
    public function testALinkRemovedIsChanged(): void
    {
        $this->linkTheSubject();

        $start      = $this->start();
        $completion = $this->complete();

        Link::query()->delete();

        $this->assertRefused($completion, $start, FailureReason::LINK_CHANGED);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * A link that now names another identity is changed, by the same id.
     *
     * @return void
     */
    public function testALinkOfAnotherIdentityIsChanged(): void
    {
        $this->linkTheSubject();

        $start      = $this->start();
        $completion = $this->complete();

        Link::query()->sole()->forceFill(['identity_id' => '8'])->save();

        $this->assertRefused($completion, $start, FailureReason::LINK_CHANGED);
    }

    /**
     * A link suspended since completion is `link_suspended`.
     *
     * @return void
     */
    public function testALinkSuspendedAtRedemptionIsSuspended(): void
    {
        $this->linkTheSubject();

        $start      = $this->start();
        $completion = $this->complete();

        Link::query()->sole()->forceFill(['state' => LinkState::SUSPENDED, 'suspended_at' => $this->clock->now()])->save();

        $this->assertRefused($completion, $start, FailureReason::LINK_SUSPENDED);
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
    }

    /**
     * A domain link found outside the tenant at redemption is suspended for
     * good.
     *
     * @return void
     */
    public function testADomainLinkFoundOutsideTheTenantAtRedemptionIsSuspended(): void
    {
        $first = $this->start();

        self::assertTrue($this->admit($this->complete(), $first)->isAdmitted());
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);

        $this->asked = 0;

        $start      = $this->start();
        $completion = $this->complete();

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        $this->assertRefused($completion, $start, FailureReason::LINK_SUSPENDED);
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
        self::assertNotNull(Link::query()->sole()->suspended_at);

        $this->scope->verdict = ScopeVerdict::WITHIN_TENANT;

        $this->start();

        self::assertSame(FailureReason::LINK_SUSPENDED, $this->complete()->reason);
    }

    /**
     * A domain link of unknown scope at redemption refuses that attempt only.
     *
     * @return void
     */
    public function testADomainLinkOfUnknownScopeAtRedemptionRefusesThatAttempt(): void
    {
        $first = $this->start();

        self::assertTrue($this->admit($this->complete(), $first)->isAdmitted());

        $this->asked = 0;

        $start      = $this->start();
        $completion = $this->complete();
        $version    = Connection::query()->whereKey($this->connection->id)->sole()->links_version;

        $this->scope->verdict = ScopeVerdict::UNKNOWN;

        $this->assertRefused($completion, $start, FailureReason::PRINCIPAL_SCOPE_UNKNOWN);
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        self::assertNull(Link::query()->sole()->suspended_at);
        self::assertSame($version, Connection::query()->whereKey($this->connection->id)->sole()->links_version);

        $this->scope->verdict = ScopeVerdict::WITHIN_TENANT;

        $again = $this->start();

        self::assertTrue($this->admit($this->complete(), $again)->isAdmitted());
    }

    /**
     * An unlinked handoff still unlinked redeems, with no identity.
     *
     * @return void
     */
    public function testAnUnlinkedHandoffStillAbsentRedeems(): void
    {
        $this->allowUnlinkedHandoffs();

        $start  = $this->start();
        $answer = $this->admit($this->complete(), $start);

        self::assertTrue($answer->isAdmitted());
        self::assertNull($answer->linkedIdentity);
        self::assertNull($answer->linkId);
        self::assertNull($answer->evidence);
        self::assertSame(0, $this->asked);
    }

    /**
     * An unlinked handoff whose subject gained a link is changed: the handoff
     * never takes that link for its own.
     *
     * @return void
     */
    public function testAnUnlinkedHandoffWhoseSubjectGainedALinkIsChanged(): void
    {
        $this->allowUnlinkedHandoffs();

        $start      = $this->start();
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());

        $this->linkTheSubject();

        $this->assertRefused($completion, $start, FailureReason::LINK_CHANGED);
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
    }

    /**
     * A reserved code with no reservation left is `reservation_invalid`, with
     * no fallback.
     *
     * @return void
     */
    public function testAReservedCodeWithNoReservationLeftHasNoFallback(): void
    {
        config()->set('sso.applications.web.unlinked_handoffs', true);

        $offered = 0;

        Event::listen(ResultUnlinked::class, static function () use (&$offered): void {
            $offered++;
        });

        $start      = $this->start();
        $completion = $this->complete();

        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);

        Link::query()->delete();

        $this->assertRefused($completion, $start, FailureReason::RESERVATION_INVALID);
        self::assertSame(0, Link::query()->count());
        self::assertSame(0, $offered);
    }

    /**
     * A reserved code is judged by its reservation, never a link that replaced
     * it.
     *
     * @return void
     */
    public function testAReservedCodeNeverTakesALinkInItsReservationsPlace(): void
    {
        $start      = $this->start();
        $completion = $this->complete();

        Link::query()->delete();

        $this->linkTheSubject();

        $link = Link::query()->sole()->id;

        $this->assertRefused($completion, $start, FailureReason::RESERVATION_INVALID);
        self::assertSame($link, Link::query()->sole()->id);
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
    }

    /**
     * Assert the redemption is refused for the reason, reporting once and
     * asking nothing, and that the refusal spent the code.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $completion
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    private function assertRefused(CompletionResult $completion, StartResult $start, FailureReason $reason): void
    {
        $this->startRecordingEvents();

        $answer = $this->admit($completion, $start);

        self::assertTrue($answer->isRefused());
        self::assertSame($reason, $answer->reason);
        self::assertNull($answer->linkedIdentity);
        self::assertNull($answer->evidence);
        self::assertSame(0, $this->asked);

        $this->assertExactlyOneFailure(Flow::REDEMPTION, $reason);

        self::assertSame(FailureReason::REPLAYED, $this->admit($completion, $start)->reason);
    }

    /**
     * Make the subject's active link for the person.
     *
     * @return void
     */
    private function linkTheSubject(): void
    {
        app(LinkStore::class)->create(
            $this->connection,
            new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT),
            $this->person,
            LinkOrigin::PROVISIONING,
            Clients::browser(),
        );
    }

    /**
     * Let a result nobody matched take an unlinked handoff.
     *
     * @return void
     */
    private function allowUnlinkedHandoffs(): void
    {
        config()->set('sso.applications.web.unlinked_handoffs', true);

        $this->matcher->match = LinkEmailMatch::none();
    }

    /**
     * What an admission of a `sign_in` comes to, for the binding, under the
     * lock, in a transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffBinding  $binding
     * @return \SineMacula\Laravel\Sso\Handoffs\Redemption\Admission
     */
    private function admitted(HandoffBinding $binding): Admission
    {
        $result = ExampleResults::full(Purpose::SIGN_IN, $this->connection->id);

        return DB::connection(StorageConnection::name())->transaction(static function () use ($result, $binding): Admission {

            $recheck = app(HandoffRecheck::class);

            return $recheck->admit($result, $binding, $recheck->lock($result->tenantId, $result->connectionId, $result->application), Clients::browser());
        });
    }

    /**
     * Bind a linker that answers the resolution.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  $resolution
     * @return void
     */
    private function bindLinker(LinkResolution $resolution): void
    {
        $this->app?->instance(Linker::class, new readonly class ($resolution) implements Linker {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  $resolution
             */
            public function __construct(

                /** What every result resolves to. */
                private LinkResolution $resolution,
            ) {}

            /**
             * Answer the resolution.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
            {
                unset($result);

                return $this->resolution;
            }
        });
    }

    /**
     * Bind an evidence contract that counts each time it is asked, and answers
     * as given.
     *
     * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $answer
     * @return void
     */
    private function bindEvidence(?AcceptedEvidence $answer): void
    {
        $count = function (): void {
            $this->asked++;
        };

        $this->app?->instance(EvidencePolicy::class, new readonly class ($answer, $count) implements EvidencePolicy {
            /**
             * Constructor.
             *
             * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $answer
             * @param  \Closure(): void  $count
             */
            public function __construct(

                /** What it answers. */
                private ?AcceptedEvidence $answer,

                /** What counts each time it is asked. */
                private \Closure $count,
            ) {}

            /**
             * Count the question, and answer.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \Carbon\CarbonImmutable  $now
             * @return ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence
             */
            #[\Override]
            public function evaluate(VerifiedResult $result, SsoConnection $connection, CarbonImmutable $now): ?AcceptedEvidence
            {
                unset($result, $connection, $now);

                ($this->count)();

                return $this->answer;
            }
        });
    }
}
