<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\Rules\LinkRules;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\LinkConfirmed;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\LinkSuspended;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffEvents;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\Redemption\LinkBranch;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Linking\RefusingLinkEligibility;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkEvents;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Pins what a `link` flow reports, each sequence and every context whole
 * (SSO-5.11, SSO-8.8, SSO-10.1, SSO-10.2, SSO-10.4): creating a link,
 * confirming one, the idempotent case, a refusal at completion and at
 * redemption; and that nothing is reported when the caller's transaction rolls
 * back (SSO-10.5). No event carries the subject, the email, the code or the
 * verifier, and a refusal never names the identity that holds the subject.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkBranch::class)]
#[CoversClass(LinkRules::class)]
#[CoversClass(LinkStore::class)]
#[CoversClass(LinkEvents::class)]
#[CoversClass(LinkConfirmed::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(HandoffEvents::class)]
final class LinkPurposeEventSequenceTest extends LinkingTestCase
{
    /** @var string When every event occurs. */
    private const string OCCURRED_AT = '2026-11-01T09:30:00.000000Z';

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
     * Creating a link: started, verified, issued, then, at redemption, created
     * with the `link_purpose` origin and redeemed; every context the same.
     *
     * @return void
     */
    public function testCreatingALinkReportsItsSequence(): void
    {
        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, HandoffIssued::class]);

        self::assertTrue($this->admit($completion, $start, Purpose::LINK, $this->person)->isRedeemed());

        $this->assertEventSequence([
            AuthorizationRequestStarted::class,
            ResultVerified::class,
            HandoffIssued::class,
            LinkCreated::class,
            HandoffRedeemed::class,
        ]);

        $context = $this->context($start);

        $this->assertContexts([$context, $context, $context, $context, $context]);

        $created = $this->recordedEvents()[3];

        self::assertInstanceOf(LinkCreated::class, $created);
        self::assertSame(LinkOrigin::LINK_PURPOSE, $created->origin);
    }

    /**
     * Confirming a link on a verified domain: started, verified, issued, then
     * confirmed and redeemed, with no link created.
     *
     * @return void
     */
    public function testConfirmingALinkReportsItsSequence(): void
    {
        $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);
        $this->startRecordingEvents();

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        self::assertTrue($this->admit($completion, $start, Purpose::LINK, $this->person)->isRedeemed());

        $this->assertEventSequence([
            AuthorizationRequestStarted::class,
            ResultVerified::class,
            HandoffIssued::class,
            LinkConfirmed::class,
            HandoffRedeemed::class,
        ]);

        $context = $this->context($start);

        $this->assertContexts([$context, $context, $context, $context, $context]);
    }

    /**
     * A subject whose scope has widened: completion latches the suspension and
     * reports it, naming only the connection and the holder; the redemption
     * reports no second one, and confirms it.
     *
     * @return void
     */
    public function testConfirmingAScopeWidenedLinkReportsTheSuspensionThenTheConfirmation(): void
    {
        $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);
        $this->startRecordingEvents();

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
        self::assertTrue($this->admit($completion, $start, Purpose::LINK, $this->person)->isRedeemed());

        $this->assertEventSequence([
            AuthorizationRequestStarted::class,
            LinkSuspended::class,
            ResultVerified::class,
            HandoffIssued::class,
            LinkConfirmed::class,
            HandoffRedeemed::class,
        ]);

        $context = $this->context($start);

        $this->assertContexts([$context, $this->suspensionContext($this->person), $context, $context, $context, $context]);
    }

    /**
     * A link with no domain provenance, observed at completion and still there:
     * neither created nor confirmed, only redeemed.
     *
     * @return void
     */
    public function testAnIdempotentLinkReportsOnlyItsRedemption(): void
    {
        $this->hold($this->person);
        $this->startRecordingEvents();

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        self::assertTrue($this->admit($completion, $start, Purpose::LINK, $this->person)->isRedeemed());

        $this->assertEventSequence([
            AuthorizationRequestStarted::class,
            ResultVerified::class,
            HandoffIssued::class,
            HandoffRedeemed::class,
        ]);

        $context = $this->context($start);

        $this->assertContexts([$context, $context, $context, $context]);
    }

    /**
     * A subject unlinked at completion and linked to the bound identity since:
     * only the redemption, again.
     *
     * @return void
     */
    public function testALinkMadeSinceCompletionReportsOnlyItsRedemption(): void
    {
        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        $this->hold($this->person);
        $this->startRecordingEvents();

        self::assertTrue($this->admit($completion, $start, Purpose::LINK, $this->person)->isRedeemed());

        $this->assertEventSequence([HandoffRedeemed::class]);
        $this->assertContexts([$this->context($start)]);
    }

    /**
     * An identity that may not link is refused at completion: verified, then
     * one failure of the callback flow, with no handoff.
     *
     * @return void
     */
    public function testARefusalAtCompletionForEligibilityReportsItsSequence(): void
    {
        $this->app?->instance(LinkEligibility::class, new RefusingLinkEligibility);

        $start = $this->start(Purpose::LINK, $this->person);

        self::assertSame(FailureReason::LINK_INELIGIBLE, $this->complete()->reason);

        $this->assertCompletionRefused(FailureReason::LINK_INELIGIBLE, $start);
    }

    /**
     * A subject linked to another identity is refused at completion, and the
     * context names only the flow's identity.
     *
     * @return void
     */
    public function testARefusalAtCompletionForAnotherHolderNamesNobody(): void
    {
        $this->hold(new IdentityReference('App\Models\User', '8'));
        $this->startRecordingEvents();

        $start = $this->start(Purpose::LINK, $this->person);

        self::assertSame(FailureReason::SUBJECT_ALREADY_LINKED, $this->complete()->reason);

        $this->assertCompletionRefused(FailureReason::SUBJECT_ALREADY_LINKED, $start);
    }

    /**
     * A subject held by a live reservation is refused at completion.
     *
     * @return void
     */
    public function testARefusalAtCompletionForAReservationReportsItsSequence(): void
    {
        $this->start();
        $this->complete();
        $this->startRecordingEvents();

        $start = $this->start(Purpose::LINK, $this->person);

        self::assertSame(FailureReason::LINK_RESERVED, $this->complete()->reason);

        $this->assertCompletionRefused(FailureReason::LINK_RESERVED, $start);
    }

    /**
     * A refusal at redemption reports exactly one failure of the redemption
     * flow, after what completion reported, and names the bound identity rather
     * than the caller.
     *
     * @return void
     */
    public function testARefusalAtRedemptionReportsExactlyOneFailure(): void
    {
        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        self::assertSame(
            FailureReason::IDENTITY_MISMATCH,
            $this->admit($completion, $start, Purpose::LINK, new IdentityReference('App\Models\User', '8'))->reason,
        );

        $this->assertEventSequence([
            AuthorizationRequestStarted::class,
            ResultVerified::class,
            HandoffIssued::class,
            FlowFailed::class,
        ]);

        $context = $this->context($start);

        $this->assertContexts([$context, $context, $context, $context]);
        $this->assertExactlyOneFailure(Flow::REDEMPTION, FailureReason::IDENTITY_MISMATCH);
    }

    /**
     * The link of another identity, found outside the tenant at redemption, is
     * suspended and reported as that identity's own; the refusal still names
     * only the bound identity, and the suspension stands.
     *
     * @return void
     */
    public function testARefusalAtRedemptionNamesOnlyTheBoundIdentity(): void
    {
        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();
        $other      = new IdentityReference('App\Models\User', '8');

        $this->hold($other, LinkOrigin::VERIFIED_DOMAIN);
        $this->startRecordingEvents();

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        self::assertSame(FailureReason::SUBJECT_ALREADY_LINKED, $this->admit($completion, $start, Purpose::LINK, $this->person)->reason);

        $this->assertEventSequence([LinkSuspended::class, FlowFailed::class]);
        $this->assertContexts([$this->suspensionContext($other), $this->context($start)]);
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
    }

    /**
     * Nothing a redemption reports survives the caller's rollback, a created
     * link's event included; the link and the consumption roll back with it,
     * and a retry of the whole transaction reports it once.
     *
     * @return void
     */
    public function testEventsAreAbsentAfterTheCallersRollback(): void
    {
        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        $this->startRecordingEvents();
        $this->admitThenRollBack($completion, $start);

        $this->assertNoEvents();
        self::assertSame(0, Link::query()->count());

        self::assertTrue($this->admit($completion, $start, Purpose::LINK, $this->person)->isRedeemed());

        $this->assertEventSequence([LinkCreated::class, HandoffRedeemed::class]);
    }

    /**
     * A confirmation rolled back by the caller reports nothing, and the link
     * stays on its verified domain.
     *
     * @return void
     */
    public function testAConfirmationIsNotReportedAfterTheCallersRollback(): void
    {
        $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        $this->startRecordingEvents();
        $this->admitThenRollBack($completion, $start);

        $this->assertNoEvents();
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, Link::query()->sole()->provenance);
    }

    /**
     * A refusal rolled back by the caller reports nothing either.
     *
     * @return void
     */
    public function testARefusalIsNotReportedAfterTheCallersRollback(): void
    {
        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        $this->app?->instance(Freshness::class, FakeFreshness::stale());

        $this->startRecordingEvents();
        $this->admitThenRollBack($completion, $start, FailureReason::FRESHNESS_REQUIRED);

        $this->assertNoEvents();
    }

    /**
     * No event of a `link` flow carries the subject, the email, the code or the
     * verifier.
     *
     * @return void
     */
    public function testNoEventCarriesAnythingSecret(): void
    {
        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();
        $code       = (string) $completion->handoff?->code->reveal();
        $verifier   = (string) $start->verifier?->reveal();

        self::assertTrue($this->admit($completion, $start, Purpose::LINK, $this->person)->isRedeemed());

        $events   = $this->recordedEvents();
        $reported = (string) json_encode(array_map(static fn (SsoEvent $event): array => $event->context()->toArray(), $events)) . serialize($events);

        self::assertNotSame('', $reported);

        foreach ([trim(VerifyingDriver::SUBJECT), self::EMAIL, $code, $verifier] as $secret) {
            self::assertStringNotContainsString($secret, $reported);
        }
    }

    /**
     * Make a link of the subject for the identity, through the store.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @return void
     */
    private function hold(IdentityReference $identity, LinkOrigin $origin = LinkOrigin::PROVISIONING): void
    {
        $creation = app(LinkStore::class)->create($this->connection, new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT), $identity, $origin, Clients::browser());

        self::assertTrue($creation->isCreated());
    }

    /**
     * Redeem the `link` code inside a transaction that then rolls back, and
     * assert what the redemption answered inside it.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $completion
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    private function admitThenRollBack(CompletionResult $completion, StartResult $start, ?FailureReason $reason = null): void
    {
        $code     = (string) $completion->handoff?->code->reveal();
        $verifier = (string) $start->verifier?->reveal();

        try {
            DB::connection(StorageConnection::name())->transaction(function () use ($code, $verifier, $reason): void {

                $answer = app(HandoffRedemption::class)->admit(Purpose::LINK, 'web', $this->connection->id, $code, $verifier, Clients::browser(), $this->person);

                self::assertSame($reason, $answer->reason);

                throw new \RuntimeException('The caller rolled back.');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('The caller rolled back.', $exception->getMessage());
        }
    }

    /**
     * Assert the flow was verified and refused at completion for the reason:
     * started, verified, one failure of the callback flow, each with the whole
     * context of the flow.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return void
     */
    private function assertCompletionRefused(FailureReason $reason, StartResult $start): void
    {
        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, FlowFailed::class]);

        $context = $this->context($start);

        $this->assertContexts([$context, $context, $context]);
        $this->assertExactlyOneFailure(Flow::CALLBACK, $reason);
    }

    /**
     * Assert each event recorded, in order, carries the whole context.
     *
     * @param  list<array<string, ?string>>  $contexts
     * @return void
     */
    private function assertContexts(array $contexts): void
    {
        self::assertSame($contexts, array_map(static fn (SsoEvent $event): array => $event->context()->toArray(), $this->recordedEvents()));
    }

    /**
     * The whole context of an event of the flow, naming the flow's identity.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return array<string, ?string>
     */
    private function context(StartResult $start): array
    {
        return [
            'occurred_at'                 => self::OCCURRED_AT,
            'ip'                          => '203.0.113.7',
            'user_agent'                  => Clients::USER_AGENT,
            'connection_id'               => $this->connection->id,
            'connection_tenant_id'        => 'tenant-1',
            'protocol'                    => VerifyingDriver::NAME,
            'application'                 => 'web',
            'purpose'                     => 'link',
            'request_reference'           => $start->reference?->value,
            'identity_morph_class'        => $this->person->type,
            'identity_id'                 => $this->person->id,
            'acting_identity_morph_class' => null,
            'acting_identity_id'          => null,
            'principal_morph_class'       => null,
            'principal_id'                => null,
            'tenant_id'                   => null,
            'session_id'                  => null,
            'method'                      => null,
        ];
    }

    /**
     * The whole context of a link's suspension: the connection and the holder,
     * and nothing of any flow.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $holder
     * @return array<string, ?string>
     */
    private function suspensionContext(IdentityReference $holder): array
    {
        return [
            'occurred_at'                 => self::OCCURRED_AT,
            'ip'                          => '203.0.113.7',
            'user_agent'                  => Clients::USER_AGENT,
            'connection_id'               => $this->connection->id,
            'connection_tenant_id'        => 'tenant-1',
            'protocol'                    => VerifyingDriver::NAME,
            'application'                 => null,
            'purpose'                     => null,
            'request_reference'           => null,
            'identity_morph_class'        => $holder->type,
            'identity_id'                 => $holder->id,
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
