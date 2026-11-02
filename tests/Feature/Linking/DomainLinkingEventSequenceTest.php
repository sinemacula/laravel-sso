<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\LinkActivated;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\LinkSuspended;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Linking\ReservationActivation;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkEvents;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * The events each path of linking by a verified domain reports, in order and in
 * whole (SSO-8.8, SSO-10.3 to SSO-10.5): a reservation; an activation, whose
 * events name the identity, the link, the application and the request's public
 * reference and never the email; a refusal at redemption; a suspension; a
 * settings change, with nothing voided; a widening; and nothing at all of a
 * redemption the caller's transaction rolls back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkEvents::class)]
#[CoversClass(ReservationActivation::class)]
#[CoversClass(LinkActivated::class)]
#[CoversClass(LinkSuspended::class)]
final class DomainLinkingEventSequenceTest extends LinkingTestCase
{
    /** @var list<class-string<\SineMacula\Laravel\Sso\Contracts\SsoEvent>> What a reservation reports. */
    private const array RESERVATION = [AuthorizationRequestStarted::class, ResultVerified::class, HandoffIssued::class];

    /**
     * A reservation reports what any completion does, and names no identity: it
     * resolved nothing.
     *
     * @return void
     */
    public function testAReservation(): void
    {
        $this->start();
        $this->complete();

        $this->assertEventSequence(self::RESERVATION);

        $issued = $this->recordedEvents()[2];

        self::assertNull($issued->context()->identityId);
        self::assertNull($issued->context()->identityMorphClass);
        self::assertSame(AuthorizationRequest::query()->sole()->reference, $issued->context()->requestReference);
    }

    /**
     * An activation reports the link created by a verified domain, its
     * activation, then the redemption, each naming the identity, the
     * application and the request's public reference, and the activation the
     * link; none carries the email.
     *
     * @return void
     */
    public function testAnActivation(): void
    {
        $start      = $this->start();
        $completion = $this->complete();

        self::assertTrue($this->admit($completion, $start)->isRedeemed());

        $this->assertEventSequence([...self::RESERVATION, LinkCreated::class, LinkActivated::class, HandoffRedeemed::class]);

        [, , , $created, $activated, $redeemed] = $this->recordedEvents();

        self::assertInstanceOf(LinkCreated::class, $created);
        self::assertInstanceOf(LinkActivated::class, $activated);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $created->origin);
        self::assertSame(Link::query()->sole()->id, $activated->linkId);

        foreach ([$created, $activated, $redeemed] as $event) {

            $context = $event->context();

            self::assertSame($this->person->type, $context->identityMorphClass);
            self::assertSame($this->person->id, $context->identityId);
            self::assertSame('web', $context->application);
            self::assertSame('sign_in', $context->purpose);
            self::assertSame($this->connection->id, $context->connectionId);
            self::assertSame('tenant-1', $context->tenantId);
            self::assertSame(VerifyingDriver::NAME, $context->protocol);
            self::assertSame(AuthorizationRequest::query()->sole()->reference, $context->requestReference);
            self::assertStringNotContainsString(self::EMAIL, print_r($event, true));
        }
    }

    /**
     * A refusal at redemption reports one failure and no link event.
     *
     * @return void
     */
    public function testARefusalAtRedemption(): void
    {
        $start      = $this->start();
        $completion = $this->complete();

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        self::assertSame(FailureReason::RESERVATION_INVALID, $this->admit($completion, $start)->reason);

        $this->assertEventSequence([...self::RESERVATION, FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::REDEMPTION, FailureReason::RESERVATION_INVALID);
    }

    /**
     * A suspension found by a completion reports `LinkSuspended`, then the
     * failure, and no `HandoffIssued`.
     *
     * @return void
     */
    public function testASuspension(): void
    {
        $start = $this->start();

        self::assertTrue($this->admit($this->complete(), $start)->isRedeemed());

        $this->startRecordingEvents();

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        $this->start();

        self::assertSame(FailureReason::LINK_SUSPENDED, $this->complete()->reason);

        $this->assertEventSequence([AuthorizationRequestStarted::class, LinkSuspended::class, ResultVerified::class, FlowFailed::class]);

        $failure = $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::LINK_SUSPENDED);

        self::assertSame($this->connection->id, $failure->context->connectionId);

        $this->startRecordingEvents();
        $this->start();

        self::assertSame(FailureReason::LINK_SUSPENDED, $this->complete()->reason);

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, FlowFailed::class]);
    }

    /**
     * A settings change reports `ConnectionUpdated` alone: no
     * `ConnectionDisabled` and nothing about any flow, whose request and code
     * are not voided.
     *
     * @return void
     */
    public function testASettingsChange(): void
    {
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $this->start();
        $this->complete();

        $this->connection->forceFill(['linking_acknowledged_at' => null])->save();

        $this->startRecordingEvents();

        app(LinkingPolicyService::class)->change('tenant-1', $this->connection->id, ['acknowledged' => true]);

        $this->assertEventSequence([ConnectionUpdated::class]);

        self::assertSame(0, AuthorizationRequest::query()->whereNotNull('voided_at')->count());
        self::assertSame(0, HandoffCode::query()->whereNotNull('voided_at')->count());
    }

    /**
     * A widening reports each suspension after its transaction commits, and
     * nothing if it rolls back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWidening(): void
    {
        $start = $this->start();

        self::assertTrue($this->admit($this->complete(), $start)->isRedeemed());

        $this->startRecordingEvents();

        try {
            $this->connection->getConnection()->transaction(static function (): void {
                app(ScopeWidening::class)->widened(new IdentityReference('App\Models\User', '7'), 'tenant-2');

                throw new \RuntimeException('The principal could not be written.');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('The principal could not be written.', $exception->getMessage());
        }

        $this->assertNoEvents();
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);

        $this->connection->getConnection()->transaction(fn (): int => app(ScopeWidening::class)->widened($this->person, 'tenant-2'));

        $this->assertEventSequence([LinkSuspended::class]);
    }

    /**
     * A redemption the caller's transaction rolls back reports nothing and
     * undoes both the consumption and the activation, so the code can be
     * redeemed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolledBackRedemptionReportsAndKeepsNothing(): void
    {
        $start      = $this->start();
        $completion = $this->complete();
        $code       = (string) $completion->handoff?->code->reveal();
        $verifier   = (string) $start->verifier?->reveal();

        try {
            $this->connection->getConnection()->transaction(function () use ($code, $verifier): void {

                self::assertTrue(app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $this->connection->id, $code, $verifier)->isRedeemed());

                throw new \RuntimeException('The session could not be written.');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('The session could not be written.', $exception->getMessage());
        }

        $this->assertEventSequence(self::RESERVATION);

        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
        self::assertNull(HandoffCode::query()->sole()->redeemed_at);
        self::assertTrue($this->admit($completion, $start)->isRedeemed());
    }
}
