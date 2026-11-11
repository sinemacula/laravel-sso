<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\Rules\LinkRules;
use SineMacula\Laravel\Sso\Completion\Stages\CheckPurpose;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Handoffs\HandoffBinding;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RecheckLock;
use SineMacula\Laravel\Sso\Handoffs\Redemption\LinkBranch;
use SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Linking\RefusingLinkEligibility;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStorageBinding;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\Fixtures\Links\DelegatingLinkStorage;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\Fixtures\Results\ExampleResults;

/**
 * Adversarial tests of the `link` purpose through public completion and
 * redemption (SSO-5.11, SSO-8.5, SSO-8.8, SSO-9.9, SSO-2.12): possessing the
 * code and its verifier never proves the caller is the bound identity;
 * freshness and eligibility are asked again before anything is written, and
 * same-identity idempotence bypasses neither; each change to the subject's link
 * between completion and redemption comes to exactly its own refusal, naming
 * nobody; a confirming `link` clears suspension and provenance for good; and
 * every refusal after consumption leaves the code spent and reports exactly one
 * `FlowFailed`, naming only the identity the code is bound to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckPurpose::class)]
#[CoversClass(LinkBranch::class)]
#[CoversClass(LinkRules::class)]
#[CoversClass(LinkStore::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(HandoffRecheck::class)]
final class LinkBranchTest extends LinkingTestCase
{
    /** @var string Another subject the provider could assert. */
    private const string OTHER_SUBJECT = 'Another-Subject';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFreshness The freshness contract, fresh unless a test replaces it. */
    private FakeFreshness $freshness;

    /** @var list<array{0: string, 1: string, 2: string}> Every question the eligibility contract was asked: the identity's type and id, and the connection. */
    private array $eligibilityAsked = [];

    /**
     * Bind an eligibility that lets every identity link and records what it was
     * asked, and a fresh caller.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = FakeFreshness::fresh();

        $this->app?->instance(Freshness::class, $this->freshness);

        $this->bindEligibility(LinkEligibilityVerdict::ELIGIBLE);
    }

    /**
     * An unlinked subject that is still unlinked is linked to the bound
     * identity with the `link_purpose` origin: an active link, no session, no
     * proof, no acknowledged sign-in, and the connection's links version raised
     * once. Freshness and eligibility were each asked at both ends of the flow,
     * freshness for the caller of each end: at redemption, the caller the
     * redemption was made for, with its session, as given.
     *
     * @return void
     */
    public function testAnUnlinkedSubjectIsLinkedToTheBoundIdentity(): void
    {
        [$start, $completion] = $this->linkFlow();

        self::assertNull($this->storedCode($start)->link_id);

        $redeemer = new Caller(new IdentityReference('App\Models\User', '7'), 'session-of-the-redeemer');
        $before   = $this->linksVersion();
        $answer   = $this->redeem($completion, $start, $redeemer);
        $link     = Link::query()->sole();

        self::assertTrue($answer->isRedeemed());
        self::assertTrue($answer->isAdmitted());
        self::assertSame($this->person->jsonSerialize(), $answer->linkedIdentity?->jsonSerialize());
        self::assertSame($this->person->jsonSerialize(), $answer->identity?->jsonSerialize());
        self::assertSame($link->id, $answer->linkId);
        self::assertNull($answer->sessionId);
        self::assertNull($answer->evidence);
        self::assertSame([LinkState::ACTIVE, LinkOrigin::LINK_PURPOSE, false, null], [$link->state, $link->provenance, $link->domain_provenance, $link->suspended_at]);
        self::assertSame(['App\Models\User', '7'], [$link->identity_type, $link->identity_id]);
        self::assertSame(VerifyingDriver::ISSUER, $link->issuer);
        self::assertSame(VerifyingDriver::SUBJECT, $link->subject);
        self::assertSame($before + 1, $this->linksVersion());
        self::assertFalse($this->connection->refresh()->has_completed_sign_in);
        self::assertNotNull($this->storedCode($start)->redeemed_at);

        self::assertEquals(
            [
                ['operation' => FreshnessOperation::LINK_CREATE, 'max_age_seconds' => 300, 'caller' => new Caller($this->person)],
                ['operation' => FreshnessOperation::LINK_CREATE, 'max_age_seconds' => 300, 'caller' => $redeemer],
            ],
            $this->freshness->asked(),
        );
        self::assertSame($redeemer, $this->freshness->asked()[1]['caller']);
        self::assertSame(
            [['App\Models\User', '7', $this->connection->id], ['App\Models\User', '7', $this->connection->id]],
            $this->eligibilityAsked,
        );
    }

    /**
     * A `link` never reaches a session, a proof or an evidence policy, whether
     * it creates a link or confirms one: the contracts bound here would fail
     * the test if asked.
     *
     * @return void
     */
    public function testALinkMakesNoSessionAndAsksForNoEvidence(): void
    {
        $sessions = new RecordingSessions;

        $this->forbidEvidenceAndRevocation();
        $this->app?->instance(ReauthenticationSessions::class, $sessions);

        [$start, $completion] = $this->linkFlow();

        self::assertTrue($this->redeem($completion, $start, $this->person)->isRedeemed());

        Link::query()->delete();

        $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);

        [$start, $completion] = $this->linkFlow();

        $answer = $this->redeem($completion, $start, $this->person);

        self::assertTrue($answer->isRedeemed());
        self::assertNull($answer->evidence);
        self::assertNull($answer->sessionId);
        self::assertSame(0, $sessions->renewals());
        self::assertFalse($this->connection->refresh()->has_completed_sign_in);
    }

    /**
     * A purpose's rules are judged only of a state holding its consumed
     * request.
     *
     * @return void
     */
    public function testThePurposeStageNeedsAConsumedRequest(): void
    {
        $this->expectExceptionObject(new \LogicException('A purpose\'s rules are checked once the request is consumed.'));

        app(CheckPurpose::class)->run($this->arrived());
    }

    /**
     * Callers that are not the bound identity: none, another id, another type,
     * and each differing only by case or by a space.
     *
     * @return iterable<string, array{0: ?array{0: string, 1: string}}>
     */
    public static function strangers(): iterable
    {
        yield 'no caller' => [null];
        yield 'another id' => [['App\Models\User', 'Ab8']];
        yield 'another type' => [['App\Models\Admin', 'Ab7']];
        yield 'the id in another case' => [['App\Models\User', 'aB7']];
        yield 'the id upper-cased' => [['App\Models\User', 'AB7']];
        yield 'the type in another case' => [['app\models\user', 'Ab7']];
        yield 'the id with a trailing space' => [['App\Models\User', 'Ab7 ']];
    }

    /**
     * Possessing the code and its verifier proves nothing about who is calling:
     * a caller that is not the bound identity byte for byte is refused before
     * freshness or eligibility is asked again, nothing is linked, and the event
     * names only the bound identity, never the caller.
     *
     * @param  ?array{0: string, 1: string}  $stranger
     * @return void
     */
    #[DataProvider('strangers')]
    public function testACallerOtherThanTheBoundIdentityIsRefused(?array $stranger): void
    {
        $bound  = new IdentityReference('App\Models\User', 'Ab7');
        $caller = $stranger === null ? null : new Caller(new IdentityReference($stranger[0], $stranger[1]), 'session-1');

        [$start, $completion] = $this->linkFlow($bound);

        $answer = $this->redeem($completion, $start, $caller);

        $this->assertRefused($answer, FailureReason::IDENTITY_MISMATCH, $start, $bound);
        self::assertSame(0, Link::query()->count());
        self::assertCount(1, $this->freshness->asked());
        self::assertCount(1, $this->eligibilityAsked);
    }

    /**
     * The bound caller, byte for byte, is the only one let through, an id with
     * mixed case included.
     *
     * @return void
     */
    public function testTheBoundCallerByteForByteIsLetThrough(): void
    {
        $bound = new IdentityReference('App\Models\User', 'Ab7');

        [$start, $completion] = $this->linkFlow($bound);

        self::assertTrue($this->redeem($completion, $start, new IdentityReference('App\Models\User', 'Ab7'))->isRedeemed());
        self::assertSame('Ab7', Link::query()->sole()->identity_id);
    }

    /**
     * A stale caller cannot start a `link`: `sso.link.create` is asked, with
     * its maximum age, for the caller on the session it gave, and nothing is
     * stored.
     *
     * @return void
     */
    public function testAStaleCallerCannotStartALink(): void
    {
        $stale  = FakeFreshness::stale();
        $caller = new Caller($this->person, 'session-1');

        $this->app?->instance(Freshness::class, $stale);

        $start = app(AuthorizationRequestService::class)->start('web', Purpose::LINK, $this->connection->id, Clients::browser(), null, $caller);

        self::assertTrue($start->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $start->reason);
        self::assertSame([['operation' => FreshnessOperation::LINK_CREATE, 'max_age_seconds' => 300, 'caller' => $caller]], $stale->asked());
        self::assertSame(0, AuthorizationRequest::query()->count());

        $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::FRESHNESS_REQUIRED);
    }

    /**
     * Fresh at the start is not fresh at redemption: a caller gone stale
     * between is refused before eligibility is asked again, with nothing
     * written.
     *
     * @return void
     */
    public function testACallerStaleAtRedemptionThoughFreshAtStartIsRefused(): void
    {
        [$start, $completion] = $this->linkFlow();

        $stale = FakeFreshness::stale();

        $this->app?->instance(Freshness::class, $stale);

        $before = $this->linksVersion();
        $answer = $this->redeem($completion, $start, $this->person);

        $this->assertRefused($answer, FailureReason::FRESHNESS_REQUIRED, $start);
        self::assertEquals([['operation' => FreshnessOperation::LINK_CREATE, 'max_age_seconds' => 300, 'caller' => new Caller($this->person)]], $stale->asked());
        self::assertSame(0, Link::query()->count());
        self::assertSame($before, $this->linksVersion());
        self::assertCount(1, $this->eligibilityAsked);
    }

    /**
     * Same-identity idempotence does not bypass freshness: a stale caller is
     * refused though the subject is already linked to it, and a suspension it
     * would have confirmed stays.
     *
     * @return void
     */
    public function testAnIdempotentLinkStillNeedsAFreshCaller(): void
    {
        $link = $this->suspended($this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN));

        [$start, $completion] = $this->linkFlow();

        $this->app?->instance(Freshness::class, FakeFreshness::stale());

        $this->assertRefused($this->redeem($completion, $start, $this->person), FailureReason::FRESHNESS_REQUIRED, $start);
        $this->assertStillSuspended($link);
    }

    /**
     * With the default contract no identity may link: completion refuses, with
     * no code issued and nothing linked.
     *
     * @return void
     */
    public function testTheDefaultEligibilityRefusesAtCompletion(): void
    {
        $this->app?->instance(LinkEligibility::class, new RefusingLinkEligibility);

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        $this->assertRefusedAtCompletion($completion, FailureReason::LINK_INELIGIBLE, $start);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Eligibility withdrawn between completion and redemption refuses, with
     * nothing linked.
     *
     * @return void
     */
    public function testEligibilityWithdrawnBeforeRedemptionIsRefused(): void
    {
        [$start, $completion] = $this->linkFlow();

        $this->bindEligibility(LinkEligibilityVerdict::INELIGIBLE);

        $this->assertRefused($this->redeem($completion, $start, $this->person), FailureReason::LINK_INELIGIBLE, $start);
        self::assertSame(0, Link::query()->count());
        self::assertCount(2, $this->eligibilityAsked);
    }

    /**
     * Same-identity idempotence does not bypass eligibility either: the link
     * the identity holds is left exactly as it was, unconfirmed.
     *
     * @return void
     */
    public function testAnIdempotentLinkStillNeedsEligibility(): void
    {
        $link = $this->suspended($this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN));

        [$start, $completion] = $this->linkFlow();

        $this->bindEligibility(LinkEligibilityVerdict::INELIGIBLE);

        $this->assertRefused($this->redeem($completion, $start, $this->person), FailureReason::LINK_INELIGIBLE, $start);
        $this->assertStillSuspended($link);
    }

    /**
     * The checks common to every purpose come first: a connection disabled
     * since completion refuses before the caller is even judged.
     *
     * @return void
     */
    public function testAConnectionNoLongerUsableRefusesBeforeTheCaller(): void
    {
        [$start, $completion] = $this->linkFlow();

        $this->connection->forceFill(['enabled' => false])->save();

        $this->assertRefused($this->redeem($completion, $start, null), FailureReason::CONNECTION_UNAVAILABLE, $start);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Unlinked at completion and now linked to the bound identity is idempotent
     * success: the link stands as it was, under its own id, and nothing is
     * raised.
     *
     * @return void
     */
    public function testALinkMadeSinceCompletionForTheBoundIdentityIsIdempotent(): void
    {
        [$start, $completion] = $this->linkFlow();

        $link   = $this->hold($this->person);
        $before = $this->linksVersion();
        $answer = $this->redeem($completion, $start, $this->person);

        self::assertTrue($answer->isRedeemed());
        self::assertSame($link->id, $answer->linkId);
        self::assertSame($this->person->jsonSerialize(), $answer->linkedIdentity?->jsonSerialize());
        self::assertSame(LinkOrigin::PROVISIONING, Link::query()->sole()->provenance);
        self::assertSame($before, $this->linksVersion());
    }

    /**
     * Unlinked at completion and since made through a verified domain for the
     * bound identity is success too, and confirms it: the person just proved
     * the caller, freshness and eligibility, and control of the subject.
     *
     * @return void
     */
    public function testADomainLinkMadeSinceCompletionForTheBoundIdentityIsConfirmed(): void
    {
        [$start, $completion] = $this->linkFlow();

        $signIn     = $this->start();
        $signInCode = $this->complete();

        self::assertTrue($this->admit($signInCode, $signIn)->isRedeemed());

        $link   = Link::query()->sole();
        $before = $this->linksVersion();

        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $link->provenance);

        $answer = $this->redeem($completion, $start, $this->person);

        self::assertTrue($answer->isRedeemed());
        self::assertSame($link->id, $answer->linkId);
        self::assertSame(LinkOrigin::LINK_PURPOSE, Link::query()->sole()->provenance);
        self::assertSame($before + 1, $this->linksVersion());
    }

    /**
     * Linked to the bound identity at completion with that same link still
     * there passes, by its id: the link is bound to the code at completion and
     * answered at redemption, and one with no domain provenance is left as it
     * was, with nothing raised.
     *
     * @return void
     */
    public function testTheSameLinkStillPresentPasses(): void
    {
        $link = $this->hold($this->person);

        [$start, $completion] = $this->linkFlow();

        self::assertSame($link->id, $this->storedCode($start)->link_id);

        $before = $this->linksVersion();
        $answer = $this->redeem($completion, $start, $this->person);

        self::assertTrue($answer->isRedeemed());
        self::assertSame($link->id, $answer->linkId);
        self::assertSame(LinkOrigin::PROVISIONING, Link::query()->sole()->provenance);
        self::assertSame(1, Link::query()->count());
        self::assertSame($before, $this->linksVersion());
    }

    /**
     * A link observed at completion, then deleted and made again for the very
     * same identity, has another id: `link_changed`, and the new link is left
     * as it is. Identity equality alone would have hidden it.
     *
     * @return void
     */
    public function testALinkDeletedAndMadeAgainForTheSameIdentityIsLinkChanged(): void
    {
        $old = $this->hold($this->person);

        [$start, $completion] = $this->linkFlow();

        $old->delete();

        $new = $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);

        self::assertNotSame($old->id, $new->id);

        $before = $this->linksVersion();

        $this->assertRefused($this->redeem($completion, $start, $this->person), FailureReason::LINK_CHANGED, $start);

        $row = Link::query()->sole();

        self::assertSame($new->id, $row->id);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $row->provenance);
        self::assertSame($before, $this->linksVersion());
    }

    /**
     * A link observed at completion and gone since is `link_changed`, never
     * made again: nothing is linked.
     *
     * @return void
     */
    public function testALinkRemovedSinceCompletionIsLinkChanged(): void
    {
        $link = $this->hold($this->person);

        [$start, $completion] = $this->linkFlow();

        $link->delete();

        $this->assertRefused($this->redeem($completion, $start, $this->person), FailureReason::LINK_CHANGED, $start);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * A link reassigned to another identity is `subject_already_linked`, and
     * the refusal names nobody but the bound identity: the whole context is
     * pinned in `assertRefused()`.
     *
     * @return void
     */
    public function testALinkReassignedToAnotherIdentityIsRefusedNamingNobody(): void
    {
        $link = $this->hold($this->person);

        [$start, $completion] = $this->linkFlow();

        $link->forceFill(['identity_id' => '8'])->save();

        $this->assertRefused($this->redeem($completion, $start, $this->person), FailureReason::SUBJECT_ALREADY_LINKED, $start);

        $row = Link::query()->sole();

        self::assertSame(['8', LinkOrigin::PROVISIONING], [$row->identity_id, $row->provenance]);
    }

    /**
     * A subject linked to another identity at completion is refused there,
     * naming nobody, with no code issued.
     *
     * @return void
     */
    public function testASubjectLinkedElsewhereAtCompletionIsRefused(): void
    {
        $this->hold(new IdentityReference('App\Models\User', '8'));

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        $this->assertRefusedAtCompletion($completion, FailureReason::SUBJECT_ALREADY_LINKED, $start);
        self::assertSame('8', Link::query()->sole()->identity_id);
    }

    /**
     * A subject linked to another identity since completion is refused at
     * redemption, naming nobody.
     *
     * @return void
     */
    public function testASubjectLinkedElsewhereAtRedemptionIsRefused(): void
    {
        [$start, $completion] = $this->linkFlow();

        $this->hold(new IdentityReference('App\Models\User', '8'));

        $this->assertRefused($this->redeem($completion, $start, $this->person), FailureReason::SUBJECT_ALREADY_LINKED, $start);
        self::assertSame('8', Link::query()->sole()->identity_id);
    }

    /**
     * A subject held by a live reservation at completion is busy: refused, and
     * the reservation is neither converted nor superseded.
     *
     * @return void
     */
    public function testALiveReservationAtCompletionIsBusy(): void
    {
        $this->start();
        $this->complete();

        $reservation = (string) Link::query()->sole()->reservation_id;

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        $this->assertRefusedAtCompletion($completion, FailureReason::LINK_RESERVED, $start);

        $row = Link::query()->sole();

        self::assertSame([LinkState::RESERVED, $reservation], [$row->state, $row->reservation_id]);
    }

    /**
     * A subject taken by a live reservation since completion is busy too, even
     * for the identity the reservation matched; the other flow's reservation
     * survives untouched, and its own redemption still activates it.
     *
     * @return void
     */
    public function testALiveReservationAtRedemptionIsBusyAndSurvives(): void
    {
        [$start, $completion] = $this->linkFlow();

        $signIn     = $this->start();
        $signInCode = $this->complete();
        $reserved   = Link::query()->sole();

        self::assertSame($this->person->id, $reserved->identity_id);

        $this->assertRefused($this->redeem($completion, $start, $this->person), FailureReason::LINK_RESERVED, $start);

        $row = Link::query()->sole();

        self::assertSame([LinkState::RESERVED, $reserved->id, $reserved->reservation_id], [$row->state, $row->id, $row->reservation_id]);

        self::assertTrue($this->admit($signInCode, $signIn)->isRedeemed());
        self::assertSame([LinkState::ACTIVE, LinkOrigin::VERIFIED_DOMAIN], [Link::query()->sole()->state, Link::query()->sole()->provenance]);
    }

    /**
     * A reservation expiring a second from now is still live, at completion,
     * since it has not expired.
     *
     * @return void
     */
    public function testAReservationExpiringOneSecondFromNowIsStillLiveAtCompletion(): void
    {
        $this->start();
        $this->complete();
        $this->reservationExpiresIn(1);

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        $this->assertRefusedAtCompletion($completion, FailureReason::LINK_RESERVED, $start);
    }

    /**
     * A reservation expiring a second from now is still live at redemption.
     *
     * @return void
     */
    public function testAReservationExpiringOneSecondFromNowIsStillLiveAtRedemption(): void
    {
        [$start, $completion] = $this->linkFlow();

        $this->start();
        $this->complete();
        $this->reservationExpiresIn(1);

        $this->assertRefused($this->redeem($completion, $start, $this->person), FailureReason::LINK_RESERVED, $start);
        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
    }

    /**
     * Seconds from now a reservation expires at for which it is logically
     * absent: at the very instant, and before it.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function expiries(): iterable
    {
        yield 'at this instant' => [0];
        yield 'a second ago' => [-1];
    }

    /**
     * An expired reservation is logically absent at completion and at
     * redemption: the code is bound to no link, the row is replaced by an
     * active link with its own id and no reservation fields, the links version
     * is raised for the deletion and the creation, and the reservation's own
     * handoff can never activate anything.
     *
     * @param  int  $seconds
     * @return void
     */
    #[DataProvider('expiries')]
    public function testAnExpiredReservationIsLogicallyAbsent(int $seconds): void
    {
        $signIn     = $this->start();
        $signInCode = $this->complete();
        $reserved   = Link::query()->sole();

        $this->reservationExpiresIn($seconds);

        [$start, $completion] = $this->linkFlow();

        self::assertNull($this->storedCode($start)->link_id);

        $before = $this->linksVersion();
        $answer = $this->redeem($completion, $start, $this->person);
        $link   = Link::query()->sole();

        self::assertTrue($answer->isRedeemed());
        self::assertNotSame($reserved->id, $link->id);
        self::assertSame($link->id, $answer->linkId);
        self::assertSame([LinkState::ACTIVE, LinkOrigin::LINK_PURPOSE, null, null], [$link->state, $link->provenance, $link->reservation_id, $link->reservation_expires_at]);
        self::assertSame($before + 2, $this->linksVersion());

        self::assertSame(FailureReason::RESERVATION_INVALID, $this->admit($signInCode, $signIn)->reason);
        self::assertSame($link->id, Link::query()->sole()->id);
    }

    /**
     * A reservation made after completion that expires before redemption is
     * logically absent too, and the link is created in its place.
     *
     * @param  int  $seconds
     * @return void
     */
    #[DataProvider('expiries')]
    public function testAReservationExpiredBetweenCompletionAndRedemptionIsReplaced(int $seconds): void
    {
        [$start, $completion] = $this->linkFlow();

        $this->start();
        $this->complete();
        $this->reservationExpiresIn($seconds);

        $answer = $this->redeem($completion, $start, $this->person);

        self::assertTrue($answer->isRedeemed());
        self::assertSame([LinkState::ACTIVE, LinkOrigin::LINK_PURPOSE], [Link::query()->sole()->state, Link::query()->sole()->provenance]);
    }

    /**
     * The link limit reached at redemption refuses: nothing is written beyond
     * the code's consumption, and the links version does not move.
     *
     * @return void
     */
    public function testTheLinkLimitReachedAtRedemptionRefuses(): void
    {
        [$start, $completion] = $this->linkFlow();

        $held   = $this->hold($this->person, LinkOrigin::PROVISIONING, self::OTHER_SUBJECT);
        $before = $this->linksVersion();

        $this->assertRefused($this->redeem($completion, $start, $this->person), FailureReason::LINK_LIMIT_REACHED, $start);
        self::assertSame($held->id, Link::query()->sole()->id);
        self::assertSame($before, $this->linksVersion());
    }

    /**
     * One link under a limit of two creates the second.
     *
     * @return void
     */
    public function testOneUnderTheLinkLimitCreates(): void
    {
        $this->bindLinkLimit(2);

        [$start, $completion] = $this->linkFlow();

        $this->hold($this->person, LinkOrigin::PROVISIONING, self::OTHER_SUBJECT);

        self::assertTrue($this->redeem($completion, $start, $this->person)->isRedeemed());
        self::assertSame(2, Link::query()->count());
    }

    /**
     * Two links under a limit of two refuses, at exactly the limit.
     *
     * @return void
     */
    public function testExactlyAtTheLinkLimitRefuses(): void
    {
        $this->bindLinkLimit(2);

        [$start, $completion] = $this->linkFlow();

        $this->hold($this->person, LinkOrigin::PROVISIONING, self::OTHER_SUBJECT);
        $this->hold($this->person, LinkOrigin::PROVISIONING, self::OTHER_SUBJECT . '-2');

        $this->assertRefused($this->redeem($completion, $start, $this->person), FailureReason::LINK_LIMIT_REACHED, $start);
        self::assertSame(2, Link::query()->count());
    }

    /**
     * A wrapper that answers absent while the row is there meets the unique
     * index at insertion: `subject_already_linked`, nothing written, the row
     * left as it was and the code spent.
     *
     * @return void
     */
    public function testAUniqueCollisionAtInsertionRefuses(): void
    {
        [$start, $completion] = $this->linkFlow();

        $row = $this->hold(new IdentityReference('App\Models\User', '8'));

        $this->app?->instance(Linker::class, new DelegatingLinkStorage(app(LinkStore::class), LinkResolution::absent()));

        $before = $this->linksVersion();

        $this->assertRefused($this->redeem($completion, $start, $this->person), FailureReason::SUBJECT_ALREADY_LINKED, $start);

        $stored = Link::query()->sole();

        self::assertSame([$row->id, '8'], [$stored->id, $stored->identity_id]);
        self::assertSame($before, $this->linksVersion());
    }

    /**
     * A link suspended on the bound identity goes through completion, bound by
     * its id; its redemption clears the suspension and the provenance, raises
     * the links version once, and a sign-in then resolves through it whatever
     * the person's scope has become, without the scope even being asked: for
     * good.
     *
     * @return void
     */
    public function testAConfirmationClearsASuspensionAndItsProvenanceForGood(): void
    {
        $link = $this->suspended($this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN));

        [$start, $completion] = $this->linkFlow();

        self::assertSame($link->id, $this->storedCode($start)->link_id);
        self::assertNull($this->storedCode($start)->linked_identity_id);

        $before = $this->linksVersion();
        $answer = $this->redeem($completion, $start, $this->person);
        $row    = Link::query()->sole();

        self::assertTrue($answer->isRedeemed());
        self::assertSame($link->id, $answer->linkId);
        self::assertSame(
            [$link->id, LinkState::ACTIVE, LinkOrigin::LINK_PURPOSE, false, null],
            [$row->id, $row->state, $row->provenance, $row->domain_provenance, $row->suspended_at],
        );
        self::assertSame($before + 1, $this->linksVersion());

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;
        $this->scope->asked   = [];

        $this->start();

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        self::assertSame([], $this->scope->asked);
    }

    /**
     * An active link on a verified domain is confirmed as well: its provenance
     * is cleared, so a later scope change no longer suspends it.
     *
     * @return void
     */
    public function testAnActiveDomainLinkIsConfirmed(): void
    {
        $link = $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);

        [$start, $completion] = $this->linkFlow();

        $before = $this->linksVersion();

        self::assertTrue($this->redeem($completion, $start, $this->person)->isRedeemed());

        $row = Link::query()->sole();

        self::assertSame([$link->id, LinkState::ACTIVE, LinkOrigin::LINK_PURPOSE, null], [$row->id, $row->state, $row->provenance, $row->suspended_at]);
        self::assertSame($before + 1, $this->linksVersion());
    }

    /**
     * A second confirmation of a link already confirmed passes and changes
     * nothing: the links version does not move again.
     *
     * @return void
     */
    public function testConfirmingAConfirmedLinkChangesNothing(): void
    {
        $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);

        [$firstStart, $first]   = $this->linkFlow();
        [$secondStart, $second] = $this->linkFlow();

        self::assertTrue($this->redeem($first, $firstStart, $this->person)->isRedeemed());

        $before = $this->linksVersion();

        self::assertTrue($this->redeem($second, $secondStart, $this->person)->isRedeemed());
        self::assertSame($before, $this->linksVersion());
    }

    /**
     * A person whose scope widened since completion has their link suspended by
     * the redemption's own resolution, and confirmed by it: the raise for each
     * is one, and the link ends confirmed.
     *
     * @return void
     */
    public function testALinkSuspendedByTheRedemptionItselfIsConfirmedByIt(): void
    {
        $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);

        [$start, $completion] = $this->linkFlow();

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        $before = $this->linksVersion();

        self::assertTrue($this->redeem($completion, $start, $this->person)->isRedeemed());

        $row = Link::query()->sole();

        self::assertSame([LinkState::ACTIVE, LinkOrigin::LINK_PURPOSE, null], [$row->state, $row->provenance, $row->suspended_at]);
        self::assertSame($before + 2, $this->linksVersion());
    }

    /**
     * A suspension held by another identity is refused at completion, with the
     * link left suspended and unconfirmed.
     *
     * @return void
     */
    public function testASuspensionHeldByAnotherIdentityIsRefusedAtCompletion(): void
    {
        $link = $this->suspended($this->hold(new IdentityReference('App\Models\User', '8'), LinkOrigin::VERIFIED_DOMAIN));

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        $this->assertRefusedAtCompletion($completion, FailureReason::SUBJECT_ALREADY_LINKED, $start);
        $this->assertStillSuspended($link);
    }

    /**
     * A suspension another identity came to hold since completion is refused at
     * redemption, and that identity's link is never confirmed.
     *
     * @return void
     */
    public function testASuspensionHeldByAnotherIdentityIsRefusedAtRedemption(): void
    {
        [$start, $completion] = $this->linkFlow();

        $link = $this->suspended($this->hold(new IdentityReference('App\Models\User', '8'), LinkOrigin::VERIFIED_DOMAIN));

        $this->assertRefused($this->redeem($completion, $start, $this->person), FailureReason::SUBJECT_ALREADY_LINKED, $start);
        $this->assertStillSuspended($link);
    }

    /**
     * A used code is `replayed`, whoever presents it: one `FlowFailed`, and the
     * link stands as it was made.
     *
     * @return void
     */
    public function testAUsedCodeIsReplayed(): void
    {
        [$start, $completion] = $this->linkFlow();

        self::assertTrue($this->redeem($completion, $start, $this->person)->isRedeemed());

        $link = Link::query()->sole();

        $this->assertRefused($this->redeem($completion, $start, $this->person), FailureReason::REPLAYED, $start);
        self::assertSame($link->id, Link::query()->sole()->id);
    }

    /**
     * A code refused once cannot be tried again by the rightful caller: the
     * refusal spent it, and the second try is `replayed`.
     *
     * @return void
     */
    public function testARefusalSpendsTheCodeForTheRightfulCallerToo(): void
    {
        [$start, $completion] = $this->linkFlow();

        $this->assertRefused($this->redeem($completion, $start, null), FailureReason::IDENTITY_MISMATCH, $start);
        $this->assertRefused($this->redeem($completion, $start, $this->person), FailureReason::REPLAYED, $start);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * What a code may be presented with that it was not issued for.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: string, 2: ?string, 3: ?string, 4: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function mismatches(): iterable
    {
        yield 'the sign_in purpose' => [Purpose::SIGN_IN, 'web', null, null, FailureReason::PURPOSE_MISMATCH];
        yield 'the reauthenticate purpose' => [Purpose::REAUTHENTICATE, 'web', null, null, FailureReason::PURPOSE_MISMATCH];
        yield 'another application' => [Purpose::LINK, 'mobile', null, null, FailureReason::APPLICATION_MISMATCH];
        yield 'the application in another case' => [Purpose::LINK, 'WEB', null, null, FailureReason::APPLICATION_MISMATCH];
        yield 'another connection' => [Purpose::LINK, 'web', '01jbanotherconnection00000', null, FailureReason::CONNECTION_MISMATCH];
        yield 'another verifier' => [Purpose::LINK, 'web', null, str_repeat('a', 43), FailureReason::VERIFIER_MISMATCH];
        yield 'a malformed verifier' => [Purpose::LINK, 'web', null, 'short', FailureReason::VERIFIER_MISMATCH];
    }

    /**
     * A `link` code presented with anything it was not issued for is refused
     * and spent: another purpose, application or connection, or a verifier that
     * does not satisfy its challenge.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  ?string  $connectionId
     * @param  ?string  $verifier
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('mismatches')]
    public function testACodePresentedWithWhatItWasNotIssuedForIsRefused(
        Purpose $purpose,
        string $application,
        ?string $connectionId,
        ?string $verifier,
        FailureReason $reason,
    ): void {
        [$start, $completion] = $this->linkFlow();

        $this->startRecordingEvents();

        $code   = (string) $completion->handoff?->code->reveal();
        $answer = $this->connection->getConnection()->transaction(fn (): RedemptionResult => app(HandoffRedemption::class)->admit(
            $purpose,
            $application,
            $connectionId ?? $this->connection->id,
            $code,
            $verifier ?? (string) $start->verifier?->reveal(),
            Clients::browser(),
            new Caller($this->person),
        ));

        $this->assertRefused($answer, $reason, $start);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * A code a second before its expiry redeems.
     *
     * @return void
     */
    public function testACodeASecondBeforeItsExpiryRedeems(): void
    {
        [$start, $completion] = $this->linkFlow();

        $this->clock->advance(59);

        self::assertTrue($this->redeem($completion, $start, $this->person)->isRedeemed());
    }

    /**
     * A code at its very expiry is refused and spent.
     *
     * @return void
     */
    public function testACodeAtItsExpiryIsRefused(): void
    {
        [$start, $completion] = $this->linkFlow();

        $this->clock->advance(60);

        $this->assertRefused($this->redeem($completion, $start, $this->person), FailureReason::HANDOFF_EXPIRED, $start);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * What a subject may resolve to at completion, and what `LinkRules` makes
     * of it for an eligible `App\Models\User` `7`.
     *
     * @return iterable<string, array{0: ?\SineMacula\Laravel\Sso\Links\LinkResolution, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function resolutions(): iterable
    {
        $bound = new IdentityReference('App\Models\User', '7');
        $other = new IdentityReference('App\Models\User', '8');

        yield 'nothing resolved' => [null, null];
        yield 'absent' => [LinkResolution::absent(), null];
        yield 'linked to the identity' => [LinkResolution::linked($bound, 'link-7'), null];
        yield 'suspended on the identity' => [LinkResolution::suspended($bound, 'link-7'), null];
        yield 'reserved' => [LinkResolution::reserved(), FailureReason::LINK_RESERVED];
        yield 'linked to another' => [LinkResolution::linked($other, 'link-8'), FailureReason::SUBJECT_ALREADY_LINKED];
        yield 'suspended on another' => [LinkResolution::suspended($other, 'link-8'), FailureReason::SUBJECT_ALREADY_LINKED];
    }

    /**
     * What `LinkRules` makes of each thing the subject may resolve to, for an
     * eligible identity.
     *
     * @param  ?\SineMacula\Laravel\Sso\Links\LinkResolution  $resolution
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $expected
     * @return void
     */
    #[DataProvider('resolutions')]
    public function testTheRulesJudgeEachResolution(?LinkResolution $resolution, ?FailureReason $expected): void
    {
        $state = $this->stateFor('App\Models\User', '7');
        $state = $resolution === null ? $state : $state->withResolution($resolution);

        self::assertSame($expected, (new LinkRules(new AllowingLinkEligibility, app(LinkStorageBinding::class)))->refusal($state));
    }

    /**
     * An identity that may not link is `link_ineligible` whatever the subject
     * resolves to: eligibility is judged first.
     *
     * @param  ?\SineMacula\Laravel\Sso\Links\LinkResolution  $resolution
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $eligible
     * @return void
     */
    #[DataProvider('resolutions')]
    public function testTheRulesRefuseAnIneligibleIdentityFirst(?LinkResolution $resolution, ?FailureReason $eligible): void
    {
        unset($eligible);

        $state = $this->stateFor('App\Models\User', '7');
        $state = $resolution === null ? $state : $state->withResolution($resolution);

        self::assertSame(FailureReason::LINK_INELIGIBLE, (new LinkRules(new RefusingLinkEligibility, app(LinkStorageBinding::class)))->refusal($state));
    }

    /**
     * The rules are reached only with a request consumed.
     *
     * @return void
     */
    public function testTheRulesNeedTheRequest(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A link is checked once its request is consumed.');

        (new LinkRules(new AllowingLinkEligibility, app(LinkStorageBinding::class)))->refusal($this->arrived()->withConnection($this->connection));
    }

    /**
     * The rules are reached only with the connection read.
     *
     * @return void
     */
    public function testTheRulesNeedTheConnection(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A link is checked once its connection is read.');

        (new LinkRules(new AllowingLinkEligibility, app(LinkStorageBinding::class)))->refusal($this->withRequest($this->arrived(), new AuthorizationRequest));
    }

    /**
     * A request that names no identity never reaches the rules through a start,
     * and is a programming error if it does.
     *
     * @return void
     */
    public function testTheRulesNeedAnIdentity(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A link flow names the identity it was started for.');

        $rules = new LinkRules(new AllowingLinkEligibility, app(LinkStorageBinding::class));

        $rules->refusal($this->withRequest($this->arrived()->withConnection($this->connection), new AuthorizationRequest));
    }

    /**
     * Admission follows a judgement that passed the caller; called directly
     * with no caller, it refuses to write.
     *
     * @return void
     */
    public function testTheBranchWritesNothingForNoCaller(): void
    {
        $result  = ExampleResults::full(Purpose::LINK, $this->connection->id);
        $lock    = RecheckLock::held('tenant-1', $this->connection->id, 'web', $this->connection, null);
        $context = new RedemptionContext($result, new HandoffBinding(identity: $this->person, trustVersion: 0), $lock, $this->connection, Clients::browser());

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A link redemption is admitted for the caller its judgement passed.');

        app(LinkBranch::class)->admit($context);
    }

    /**
     * Start and complete a `link` flow for the identity.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: \SineMacula\Laravel\Sso\Completion\CompletionResult}
     */
    private function linkFlow(?IdentityReference $identity = null): array
    {
        $start      = $this->start(Purpose::LINK, $identity ?? $this->person);
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());

        return [$start, $completion];
    }

    /**
     * Redeem the `link` code as the caller, recording only what the redemption
     * reports.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $completion
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  \SineMacula\Laravel\Sso\Identities\Caller|\SineMacula\Laravel\Sso\Identities\IdentityReference|null  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function redeem(CompletionResult $completion, StartResult $start, Caller|IdentityReference|null $caller): RedemptionResult
    {
        $this->startRecordingEvents();

        return $this->admit($completion, $start, Purpose::LINK, $caller);
    }

    /**
     * Make a link of the subject for the identity, through the store.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @param  string  $subject
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function hold(IdentityReference $identity, LinkOrigin $origin = LinkOrigin::PROVISIONING, string $subject = VerifyingDriver::SUBJECT): Link
    {
        $creation = app(LinkStore::class)->create($this->connection, new LinkSubject(VerifyingDriver::ISSUER, $subject), $identity, $origin, Clients::browser());

        self::assertTrue($creation->isCreated());

        return Link::query()->whereKey($creation->link?->id)->sole();
    }

    /**
     * Store the link's suspension, as a scope change latches it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function suspended(Link $link): Link
    {
        $link->forceFill(['state' => LinkState::SUSPENDED, 'suspended_at' => $this->clock->now()])->save();

        return $link;
    }

    /**
     * Make the only reservation expire at the seconds from now.
     *
     * @param  int  $seconds
     * @return void
     */
    private function reservationExpiresIn(int $seconds): void
    {
        $row = Link::query()->sole();

        self::assertSame(LinkState::RESERVED, $row->state);

        $row->forceFill(['reservation_expires_at' => $this->clock->now()->addSeconds($seconds)])->save();
    }

    /**
     * Bind an eligibility that answers the verdict and records what it is
     * asked.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict  $verdict
     * @return void
     */
    private function bindEligibility(LinkEligibilityVerdict $verdict): void
    {
        $record = function (IdentityReference $identity, SsoConnection $connection): void {
            $this->eligibilityAsked[] = [$identity->type, $identity->id, $connection->getConnectionId()];
        };

        $this->app?->instance(LinkEligibility::class, new readonly class ($verdict, $record) implements LinkEligibility {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict  $verdict
             * @param  \Closure(\SineMacula\Laravel\Sso\Identities\IdentityReference, \SineMacula\Laravel\Sso\Contracts\SsoConnection): void  $record
             */
            public function __construct(

                /** What it answers. */
                private LinkEligibilityVerdict $verdict,

                /** Records each question. */
                private \Closure $record,
            ) {}

            /**
             * Record the question and answer the verdict.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict
             */
            #[\Override]
            public function judge(IdentityReference $identity, SsoConnection $connection): LinkEligibilityVerdict
            {
                ($this->record)($identity, $connection);

                return $this->verdict;
            }
        });
    }

    /**
     * Bind a limit of as many links per identity and connection.
     *
     * @param  int  $links
     * @return void
     */
    private function bindLinkLimit(int $links): void
    {
        $this->app?->instance(LinkLimit::class, new readonly class ($links) implements LinkLimit {
            /**
             * Constructor.
             *
             * @param  int  $links
             */
            public function __construct(

                /** The most links it allows. */
                private int $links,
            ) {}

            /**
             * Answer the limit.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return int
             */
            #[\Override]
            public function maxLinks(IdentityReference $identity, SsoConnection $connection): int
            {
                unset($identity, $connection);

                return $this->links;
            }
        });
    }

    /**
     * Bind an evidence policy and a session revocation that fail the test if a
     * `link` ever reaches them.
     *
     * @return void
     */
    private function forbidEvidenceAndRevocation(): void
    {
        $this->app?->instance(EvidencePolicy::class, new readonly class implements EvidencePolicy {
            /**
             * A `link` is never asked about.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \Carbon\CarbonImmutable  $now
             * @return ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence
             *
             * @throws \LogicException
             */
            #[\Override]
            public function evaluate(VerifiedResult $result, SsoConnection $connection, CarbonImmutable $now): ?AcceptedEvidence
            {
                unset($result, $connection, $now);

                throw new \LogicException('A link asked for evidence.');
            }
        });

        $this->app?->instance(SessionRevocation::class, new readonly class implements SessionRevocation {
            /**
             * A `link` revokes nothing.
             *
             * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
             * @return void
             *
             * @throws \LogicException
             */
            #[\Override]
            public function revoke(RevocationScope $scope): void
            {
                unset($scope);

                throw new \LogicException('A link revoked a session.');
            }
        });
    }

    /**
     * The state of a completion that has only just arrived.
     *
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     */
    private function arrived(): CompletionState
    {
        return CompletionState::arrived($this->connection->id, new CompletionRequest('GET', 'state=1', []), Clients::browser());
    }

    /**
     * The state with the request consumed.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     */
    private function withRequest(CompletionState $state, AuthorizationRequest $request): CompletionState
    {
        $consumed    = new ConsumedRequest(Purpose::LINK, 'web', RequestReference::fromString(str_repeat('r', 32)), $this->clock->now());
        $application = Application::fromSettings(config(), 'web', ['redirect_uri' => 'https://app.example.com/sso']);

        return $state->withAuthorizationRequest($request, $consumed, $application);
    }

    /**
     * The state of a `link` for the identity, its connection read and its
     * request consumed.
     *
     * @param  string  $type
     * @param  string  $id
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     */
    private function stateFor(string $type, string $id): CompletionState
    {
        $request = new AuthorizationRequest;

        $request->forceFill(['identity_type' => $type, 'identity_id' => $id]);

        return $this->withRequest($this->arrived()->withConnection($this->connection), $request);
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
     * The connection's links version now.
     *
     * @return int
     */
    private function linksVersion(): int
    {
        return $this->connection->refresh()->links_version;
    }

    /**
     * Assert the redemption was refused for the reason, reporting exactly one
     * `FlowFailed` of the redemption flow and nothing else, whose whole context
     * names only the identity the code is bound to, and left the code spent.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $answer
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $bound
     * @return void
     */
    private function assertRefused(RedemptionResult $answer, FailureReason $reason, StartResult $start, ?IdentityReference $bound = null): void
    {
        self::assertTrue($answer->isRefused());
        self::assertSame($reason, $answer->reason);
        self::assertFalse($answer->isAdmitted());
        self::assertNull($answer->linkId);
        self::assertNull($answer->result);

        $this->assertEventSequence([FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::REDEMPTION, $reason);

        self::assertSame($this->context($start, $bound), $failure->context->toArray());
        self::assertNotNull($this->storedCode($start)->redeemed_at);
    }

    /**
     * Assert the completion ended in a refusal for the reason, with no code,
     * and reported exactly one `FlowFailed` of the callback flow, whose whole
     * context names only the identity the flow was started for.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $completion
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return void
     */
    private function assertRefusedAtCompletion(CompletionResult $completion, FailureReason $reason, StartResult $start): void
    {
        self::assertTrue($completion->isFailed());
        self::assertSame($reason, $completion->reason);
        self::assertNull($completion->handoff);
        self::assertSame(0, StoredCode::query()->where('request_reference', $start->reference?->value)->count());

        $failure = $this->assertExactlyOneFailure(Flow::CALLBACK, $reason);

        self::assertSame($this->context($start), $failure->context->toArray());
    }

    /**
     * Assert the link is still suspended, as it was made, unconfirmed.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @return void
     */
    private function assertStillSuspended(Link $link): void
    {
        $row = Link::query()->whereKey($link->id)->sole();

        self::assertSame([LinkState::SUSPENDED, LinkOrigin::VERIFIED_DOMAIN, true], [$row->state, $row->provenance, $row->domain_provenance]);
        self::assertNotNull($row->suspended_at);
    }

    /**
     * The whole context of an event of the flow, naming the bound identity.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $bound
     * @return array<string, ?string>
     */
    private function context(StartResult $start, ?IdentityReference $bound = null): array
    {
        return [
            'occurred_at'                 => $this->clock->now()->utc()->format('Y-m-d\TH:i:s.u\Z'),
            'ip'                          => '203.0.113.7',
            'user_agent'                  => Clients::USER_AGENT,
            'connection_id'               => $this->connection->id,
            'connection_tenant_id'        => 'tenant-1',
            'protocol'                    => VerifyingDriver::NAME,
            'application'                 => 'web',
            'purpose'                     => 'link',
            'request_reference'           => $start->reference?->value,
            'identity_morph_class'        => ($bound ?? $this->person)->type,
            'identity_id'                 => ($bound ?? $this->person)->id,
            'acting_identity_morph_class' => null,
            'acting_identity_id'          => null,
            'principal_morph_class'       => null,
            'principal_id'                => null,
            'tenant_id'                   => null,
            'session_id'                  => null,
            'method'                      => null,
        ];
    }
}
