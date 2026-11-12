<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn;
use SineMacula\Laravel\Sso\Completion\CompletionLocks;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\ProvisioningOffer;
use SineMacula\Laravel\Sso\Completion\Rules\LinkRules;
use SineMacula\Laravel\Sso\Completion\Rules\ReauthenticationRules;
use SineMacula\Laravel\Sso\Completion\Rules\SignInRules;
use SineMacula\Laravel\Sso\Completion\Stages\CheckPurpose;
use SineMacula\Laravel\Sso\Completion\Stages\DomainReservation;
use SineMacula\Laravel\Sso\Completion\Stages\Provisioning;
use SineMacula\Laravel\Sso\Completion\VerifiedDeadlines;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\DomainWithdrawal;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\LinkActivated;
use SineMacula\Laravel\Sso\Events\LinkConfirmed;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\LinkSuspended;
use SineMacula\Laravel\Sso\Events\ReauthenticationCompleted;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\Redemption\LinkBranch;
use SineMacula\Laravel\Sso\Handoffs\Redemption\ReauthenticationBranch;
use SineMacula\Laravel\Sso\Handoffs\Redemption\SignInBranch;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\DomainLinkEligibility;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\ReservationActivation;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Enforcement\FailingRevocation;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Linking\RecordingRevocation;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Feature tests of the linking state machine through the public completion and
 * redemption.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckPurpose::class)]
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(CompletionLocks::class)]
#[CoversClass(ProvisioningOffer::class)]
#[CoversClass(VerifiedDeadlines::class)]
#[CoversClass(SignInRules::class)]
#[CoversClass(LinkRules::class)]
#[CoversClass(ReauthenticationRules::class)]
#[CoversClass(DomainReservation::class)]
#[CoversClass(Provisioning::class)]
#[CoversClass(DomainLinkEligibility::class)]
#[CoversClass(ReservationActivation::class)]
#[CoversClass(LinkReservations::class)]
#[CoversClass(ReservationWithdrawal::class)]
#[CoversClass(LinkStore::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(SignInBranch::class)]
#[CoversClass(LinkBranch::class)]
#[CoversClass(ReauthenticationBranch::class)]
#[CoversClass(ProvisioningGrant::class)]
final class StateMachineCompletionPipelineTest extends LinkingTestCase
{
    /**
     * An eligible unlinked `sign_in` reserves in T2, and its redemption
     * activates the reservation.
     *
     * @return void
     */
    public function testAReservationFinishesInItsTransactionAndItsRedemptionActivatesIt(): void
    {
        $start      = $this->start();
        $completion = $this->complete();
        $row        = Link::query()->sole();

        self::assertTrue($completion->isCompleted());
        self::assertSame(LinkState::RESERVED, $row->state);
        self::assertSame($this->domain->id, $row->reservation_domain_id);
        self::assertSame(1, $row->reservation_domain_generation);
        self::assertSame(0, $row->reservation_linking_version);
        self::assertSame($this->person->id, $row->identity_id);
        self::assertSame($completion->handoff?->expiresAt->toIso8601String(), $row->reservation_expires_at?->toIso8601String());
        self::assertNotSame('', $row->reservation_id);
        self::assertSame(hash('sha256', "sso-reservation-email-v1\0" . $row->reservation_id . "\0" . self::EMAIL), $row->reservation_email_digest);

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, HandoffIssued::class]);

        $answer = $this->admit($completion, $start);
        $active = Link::query()->sole();

        self::assertTrue($answer->isRedeemed());
        self::assertTrue($answer->isAdmitted());
        self::assertSame($this->person->id, $answer->linkedIdentity?->id);
        self::assertSame($row->id, $answer->linkId);
        self::assertSame(LinkState::ACTIVE, $active->state);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $active->provenance);
        self::assertTrue($active->domain_provenance);
        self::assertNull($active->reservation_id);
        self::assertNull($active->reservation_expires_at);
        self::assertNull($active->reservation_email_digest);

        $this->assertEventSequence([
            AuthorizationRequestStarted::class,
            ResultVerified::class,
            HandoffIssued::class,
            LinkCreated::class,
            LinkActivated::class,
            HandoffRedeemed::class,
        ]);
    }

    /**
     * A refusal once the code is consumed deletes that code's reservation and
     * leaves the code spent: a verifier that does not match, here.
     *
     * @return void
     */
    public function testARefusalAfterConsumptionDeletesTheReservation(): void
    {
        $start      = $this->start();
        $completion = $this->complete();

        $other = str_repeat('a', 43);
        $code  = (string) $completion->handoff?->code->reveal();
        $spent = DB::connection(StorageConnection::name())->transaction(
            fn () => app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $this->connection->id, $code, $other, Clients::browser()),
        );

        self::assertSame(FailureReason::VERIFIER_MISMATCH, $spent->reason);
        self::assertSame(0, Link::query()->count());
        self::assertSame(FailureReason::REPLAYED, $this->admit($completion, $start)->reason);
    }

    /**
     * A condition failing at redemption is `reservation_invalid`, for each
     * condition, and no link is left: never a fallback to another identity.
     *
     * @return void
     */
    public function testARecheckThatFailsActivatesNothing(): void
    {
        $changes = [
            fn (): LinkEmailMatch => $this->matcher->match = LinkEmailMatch::exactlyOne(new IdentityReference('App\Models\User', '8')),
            fn (): LinkEmailMatch => $this->matcher->match = LinkEmailMatch::ambiguous(),
            fn (): ScopeVerdict => $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT,
            fn (): bool => $this->domain->forceFill(['verification_generation' => 2])->save(),
            fn (): bool => $this->domain->forceFill(['linking_suspended_at' => $this->clock->now()])->save(),
        ];

        foreach ($changes as $index => $change) {

            $this->resetFor($index);

            $start      = $this->start();
            $completion = $this->complete();

            self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);

            $change();

            self::assertSame(FailureReason::RESERVATION_INVALID, $this->admit($completion, $start)->reason, (string) $index);
            self::assertSame(0, Link::query()->count(), (string) $index);
        }
    }

    /**
     * An unlinked `sign_in` crosses the provisioning boundary with no
     * transaction open.
     *
     * @return void
     */
    public function testAnUnlinkedSignInCrossesTheProvisioningBoundary(): void
    {
        $this->matcher->match = LinkEmailMatch::none();

        $start    = $this->start();
        $request  = AuthorizationRequest::query()->sole();
        $seen     = [];
        $captured = null;

        Event::listen(ResultUnlinked::class, function (ResultUnlinked $event) use (&$seen, &$captured, $request): void {

            $stored = AuthorizationRequest::query()->whereKey($request->id)->sole();

            $seen = [
                DB::connection(StorageConnection::name())->transactionLevel(),
                $stored->verified_at !== null,
                $stored->completed_at === null,
                $event->grant->isUsable(),
                $event->grant->claim($event->result) === $request->id,
                $event->grant->claim($event->result) === null,
            ];

            $captured = $event->grant;

            app(LinkStore::class)->create($this->connection, LinkSubject::of($event->result), $this->person, LinkOrigin::PROVISIONING, Clients::browser());
        });

        $completion = $this->complete();

        self::assertSame([0, true, true, true, true, true], $seen);
        self::assertFalse($captured?->isUsable());
        self::assertTrue($completion->isCompleted());
        self::assertNotNull(AuthorizationRequest::query()->sole()->completed_at);

        $answer = $this->admit($completion, $start);

        self::assertSame($this->person->id, $answer->linkedIdentity?->id);
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        self::assertCount(1, array_filter($this->recordedEvents(), static fn ($event): bool => $event instanceof ResultVerified));
    }

    /**
     * A listener's exception ends the completion and nothing resumes it: the
     * grant is closed, the request consumed and unfinished, no handoff is kept.
     *
     * @return void
     */
    public function testAListenerExceptionTerminatesTheCompletion(): void
    {
        $this->matcher->match = LinkEmailMatch::none();

        $this->start();

        $captured = null;

        Event::listen(ResultUnlinked::class, static function (ResultUnlinked $event) use (&$captured): void {

            $captured = $event->grant;

            throw new \RuntimeException('The listener failed.');
        });

        try {
            $this->complete();
            self::fail('The completion went on.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The listener failed.', $exception->getMessage());
        }

        self::assertFalse($captured?->isUsable());
        self::assertNull(AuthorizationRequest::query()->sole()->completed_at);
        self::assertSame(0, DB::table(StorageConnection::table('handoff_codes.table'))->count());
    }

    /**
     * A listener that leaves its transaction open is a `LogicException`, and
     * what it opened is rolled back.
     *
     * @return void
     */
    public function testAListenerLeavingATransactionOpenIsALogicException(): void
    {
        $this->matcher->match = LinkEmailMatch::none();

        $this->start();

        Event::listen(ResultUnlinked::class, static function (): void {
            DB::connection(StorageConnection::name())->beginTransaction();
        });

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A provisioning listener must commit or roll back its transaction before it returns (SSO-8.6).');

        try {
            $this->complete();
        } finally {
            self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        }
    }

    /**
     * A listener that outlasts the verified response's validity is
     * `request_expired` in T3: no continuation extends the authority.
     *
     * @return void
     */
    public function testTheVerifiedDeadlineIsCheckedInTheFinalContinuation(): void
    {
        $this->matcher->match = LinkEmailMatch::none();

        config()->set('sso.applications.web.unlinked_handoffs', true);

        $this->start();

        Event::listen(ResultUnlinked::class, function (): void {
            $this->clock->advance(120);
        });

        $completion = $this->complete();

        self::assertSame(FailureReason::REQUEST_EXPIRED, $completion->reason);
        self::assertNull($completion->handoff);
    }

    /**
     * A suspended link stays suspended until a confirming `link`.
     *
     * @return void
     */
    public function testASuspendedLinkStaysSuspendedUntilAConfirmingLink(): void
    {
        $sessions = new RecordingRevocation;

        $this->app?->instance(SessionRevocation::class, $sessions);

        $this->linkByDomain();

        $version = Connection::query()->whereKey($this->connection->id)->sole()->links_version;

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        $offered = 0;

        Event::listen(ResultUnlinked::class, static function () use (&$offered): void {
            $offered++;
        });

        $this->start();

        self::assertSame(FailureReason::LINK_SUSPENDED, $this->complete()->reason);
        self::assertSame(0, $offered);
        self::assertSame([Link::query()->sole()->id], $sessions->linkIds);
        self::assertSame([2], $sessions->levels, 'In a savepoint inside the completion\'s transaction.');
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
        self::assertNotNull(Link::query()->sole()->suspended_at);
        self::assertSame($version + 1, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
        self::assertNotEmpty(array_filter($this->recordedEvents(), static fn ($event): bool => $event instanceof LinkSuspended));

        $this->scope->verdict = ScopeVerdict::WITHIN_TENANT;

        $this->start();

        self::assertSame(FailureReason::LINK_SUSPENDED, $this->complete()->reason);

        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());
        self::assertTrue($this->admit($completion, $start, Purpose::LINK, $this->person)->isRedeemed());

        $link = Link::query()->sole();

        self::assertSame(LinkState::ACTIVE, $link->state);
        self::assertSame(LinkOrigin::LINK_PURPOSE, $link->provenance);
        self::assertNull($link->suspended_at);
        self::assertNotEmpty(array_filter($this->recordedEvents(), static fn ($event): bool => $event instanceof LinkConfirmed));
        self::assertCount(1, $sessions->linkIds, 'A link already suspended is not revoked again by its resolutions.');
    }

    /**
     * An `unknown` scope verdict refuses that attempt only.
     *
     * @return void
     */
    public function testAnUnknownScopeRefusesTheAttemptOnly(): void
    {
        $sessions = new RecordingRevocation;

        $this->app?->instance(SessionRevocation::class, $sessions);

        $this->linkByDomain();

        $version = Connection::query()->whereKey($this->connection->id)->sole()->links_version;
        $offered = 0;

        Event::listen(ResultUnlinked::class, static function () use (&$offered): void {
            $offered++;
        });

        $this->scope->verdict = ScopeVerdict::UNKNOWN;

        $this->startRecordingEvents();
        $this->start();

        self::assertSame(FailureReason::PRINCIPAL_SCOPE_UNKNOWN, $this->complete()->reason);
        self::assertSame(0, $offered);
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        self::assertNull(Link::query()->sole()->suspended_at);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, Link::query()->sole()->provenance);
        self::assertSame($version, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
        self::assertSame([], $sessions->linkIds);
        self::assertSame([], array_filter($this->recordedEvents(), static fn ($event): bool => $event instanceof LinkSuspended));

        $this->scope->verdict = ScopeVerdict::WITHIN_TENANT;

        $start      = $this->start();
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());
        self::assertTrue($this->admit($completion, $start)->isRedeemed());
    }

    /**
     * A link already suspended stays suspended under a verdict of `unknown`,
     * its reason `link_suspended`, the contract not even asked.
     *
     * @return void
     */
    public function testAnUnknownScopeLeavesASuspendedLinkSuspended(): void
    {
        $this->linkByDomain();

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        $this->start();
        $this->complete();

        $this->scope->verdict = ScopeVerdict::UNKNOWN;
        $version              = Connection::query()->whereKey($this->connection->id)->sole()->links_version;

        $this->start();

        self::assertSame(FailureReason::LINK_SUSPENDED, $this->complete()->reason);
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
        self::assertSame($version, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
    }

    /**
     * A revocation failing while a link latches rolls the suspension back.
     *
     * @return void
     */
    public function testARevocationThatFailsWhileLatchingRollsTheSuspensionBack(): void
    {
        $this->linkByDomain();

        $this->app?->instance(SessionRevocation::class, new FailingRevocation);

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        $this->startRecordingEvents();
        $this->start();

        try {
            $this->complete();
            self::fail('The revocation\'s failure was swallowed.');
        } catch (\RuntimeException $exception) {
            self::assertSame(FailingRevocation::MESSAGE, $exception->getMessage());
        }

        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        self::assertNull(Link::query()->sole()->suspended_at);
        self::assertSame([], array_filter($this->recordedEvents(), static fn ($event): bool => $event instanceof LinkSuspended));
    }

    /**
     * Another flow's live reservation holds the subject.
     *
     * @return void
     */
    public function testALiveReservationHoldsTheSubject(): void
    {
        $this->start();
        $this->complete();

        $this->start();

        self::assertSame(FailureReason::LINK_RESERVED, $this->complete()->reason);

        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $this->start(Purpose::LINK, $this->person);

        self::assertSame(FailureReason::LINK_RESERVED, $this->complete()->reason);
        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
    }

    /**
     * An expired reservation is replaced, and its expired handoff is refused
     * for its own expiry.
     *
     * @return void
     */
    public function testAnExpiredReservationIsReplacedAndItsExpiredHandoffLeavesTheNewOne(): void
    {
        $old      = $this->start();
        $first    = $this->complete();
        $reserved = Link::query()->sole()->reservation_id;

        $this->clock->advance(61);
        $this->domain->forceFill(['last_successful_check_at' => $this->clock->now()])->save();

        $this->start();
        $second = $this->complete();

        $row = Link::query()->sole();

        self::assertTrue($second->isCompleted());
        self::assertNotSame($reserved, $row->reservation_id);
        self::assertSame(FailureReason::HANDOFF_EXPIRED, $this->admit($first, $old)->reason);

        $kept = Link::query()->sole();

        self::assertSame(LinkState::RESERVED, $kept->state);
        self::assertSame($row->reservation_id, $kept->reservation_id);
    }

    /**
     * A reverified claim's new generation activates no older reservation. The
     * lapse is forced, since the rechecker's withdrawal would delete the
     * reservation first.
     *
     * @return void
     */
    public function testAReverificationThroughTheServiceActivatesNothing(): void
    {
        $start      = $this->start();
        $completion = $this->complete();
        $dns        = new FakeDnsResolver;

        self::assertSame(1, Link::query()->sole()->reservation_domain_generation);

        $this->app?->instance(DnsResolver::class, $dns);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $this->domain->forceFill(['state' => DomainState::LAPSED, 'verified_domain' => null, 'lapsed_at' => $this->clock->now()])->save();

        $dns->found('_sso-verification.example.com', $this->domain->verification_token);

        $verified = app(DomainService::class)->verify('tenant-1', $this->connection->id, 'example.com', Clients::browser());

        self::assertSame(DomainStatus::VERIFIED, $verified->status, (string) $verified->reason?->value);
        self::assertSame(2, $this->domain->refresh()->verification_generation);
        self::assertSame(1, Link::query()->sole()->reservation_domain_generation);

        self::assertSame(FailureReason::RESERVATION_INVALID, $this->admit($completion, $start)->reason);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * A change of the organisation's value raises the linking version and
     * deletes the reservation.
     *
     * @return void
     */
    public function testAnOrganizationValueChangeWithdrawsTheReservation(): void
    {
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $start      = $this->start();
        $completion = $this->complete();

        self::assertSame(1, Link::query()->count());

        $changed = app(LinkingPolicyService::class)->change('tenant-1', $this->connection->id, ['organization_value' => 'changed.example'], Clients::browser());

        self::assertTrue($changed->isChanged());
        self::assertSame(['linking.organization_value'], $changed->changedSettings);

        $connection = Connection::query()->whereKey($this->connection->id)->sole();

        self::assertSame(1, $connection->linking_version);
        self::assertSame(0, $connection->trust_version);
        self::assertTrue($connection->linking_enabled);
        self::assertSame(0, Link::query()->count());
        self::assertSame(FailureReason::RESERVATION_INVALID, $this->admit($completion, $start)->reason);
    }

    /**
     * A completion refusing after it reserved discards the reservation.
     *
     * @return void
     */
    public function testARefusalAfterTheReservationDiscardsIt(): void
    {
        $this->start();

        config()->set('sso.applications.web.external_sign_in', false);

        $completion = $this->complete();

        self::assertTrue($completion->isFailed());
        self::assertSame(FailureReason::APPLICATION_NOT_ALLOWED, $completion->reason);
        self::assertNull($completion->handoff);
        self::assertSame(0, Link::query()->count());
        self::assertSame(2, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
        self::assertSame(0, StoredCode::query()->count());
        self::assertNotNull(AuthorizationRequest::query()->sole()->completed_at);
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::APPLICATION_NOT_ALLOWED);
    }

    /**
     * A policy bound to refuse, asked at issuance, discards the reservation the
     * same way, and leaves another subject's untouched.
     *
     * @return void
     */
    public function testARefusingPolicyDiscardsOnlyItsOwnReservation(): void
    {
        $this->start();
        $this->complete();

        $other = Link::query()->sole();

        $email   = new LinkingEmail(self::EMAIL, LinkingEmailSource::ID_TOKEN);
        $context = new AuthenticationContext($this->clock->now());

        $this->verifying->claims = new VerifiedClaims(VerifyingDriver::ISSUER, 'another-subject', null, ['mail' => self::EMAIL], $context, $email);

        $this->matcher->match = LinkEmailMatch::exactlyOne(new IdentityReference('App\Models\User', '9'));

        $this->start();

        $this->app?->instance(ApplicationPolicy::class, new readonly class implements ApplicationPolicy {
            /**
             * Refuse every application.
             *
             * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
             * @return \SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn
             */
            #[\Override]
            public function externalSignIn(Application $application): ExternalSignIn
            {
                unset($application);

                return ExternalSignIn::NOT_ALLOWED;
            }
        });

        self::assertSame(FailureReason::APPLICATION_NOT_ALLOWED, $this->complete()->reason);

        $kept = Link::query()->sole();

        self::assertSame($other->id, $kept->id);
        self::assertSame($other->reservation_id, $kept->reservation_id);
    }

    /**
     * A reservation the unique index refuses goes on to `unlinked`, leaving the
     * other row alone.
     *
     * @return void
     */
    public function testAReservationTheUniqueIndexRefusesGoesOnWithNone(): void
    {
        $subject = new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT);
        $forged  = $this->makeLink($this->connection, 'not-the-subject', [
            'issuer'        => VerifyingDriver::ISSUER,
            'subject_key'   => $subject->key(),
            'identity_type' => 'App\Models\User',
            'identity_id'   => 'another',
            'state'         => LinkState::ACTIVE,
            'provenance'    => LinkOrigin::PROVISIONING,
        ]);
        $version = Connection::query()->whereKey($this->connection->id)->sole()->links_version;

        $this->start();

        $completion = $this->complete();

        self::assertSame(FailureReason::UNLINKED, $completion->reason);

        $kept = Link::query()->sole();

        self::assertSame($forged->id, $kept->id);
        self::assertSame(LinkState::ACTIVE, $kept->state);
        self::assertSame('another', $kept->identity_id);
        self::assertSame($version, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
    }

    /**
     * A `link` needs the bound caller, and makes no session.
     *
     * @return void
     */
    public function testALinkNeedsTheBoundCaller(): void
    {
        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();
        $stranger   = new IdentityReference('App\Models\User', '8');

        self::assertSame(FailureReason::IDENTITY_MISMATCH, $this->admit($completion, $start, Purpose::LINK, $stranger)->reason);
        self::assertSame(0, Link::query()->count());

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();
        $answer     = $this->admit($completion, $start, Purpose::LINK, $this->person);

        self::assertTrue($answer->isRedeemed());
        self::assertSame(LinkOrigin::LINK_PURPOSE, Link::query()->sole()->provenance);
        self::assertSame($answer->linkId, Link::query()->sole()->id);
    }

    /**
     * A `reauthenticate` needs the exact link, and is refused standalone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationNeedsTheExactLink(): void
    {
        $this->linkByProvisioning();

        $link     = Link::query()->sole();
        $sessions = new RecordingSessions('another-link');

        $this->app?->instance(ReauthenticationSessions::class, $sessions);

        $start      = $this->start(Purpose::REAUTHENTICATE, $this->person, 'session-1');
        $completion = $this->complete();

        self::assertSame(FailureReason::SESSION_INELIGIBLE, $this->admit($completion, $start, Purpose::REAUTHENTICATE)->reason);
        self::assertSame(0, $sessions->renewals());

        $sessions->boundLink = $link->id;

        $start      = $this->start(Purpose::REAUTHENTICATE, $this->person, 'session-1');
        $completion = $this->complete();
        $code       = (string) $completion->handoff?->code->reveal();
        $verifier   = (string) $start->verifier?->reveal();

        try {
            app(HandoffRedemption::class)->redeem(Purpose::REAUTHENTICATE, 'web', $this->connection->id, $code, $verifier, Clients::browser());
            self::fail('The standalone path redeemed a reauthentication.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString('admit()', $exception->getMessage());
        }

        $answer = $this->admit($completion, $start, Purpose::REAUTHENTICATE);

        self::assertTrue($answer->isAdmitted());
        self::assertSame($link->id, $answer->linkId);
        self::assertSame(1, $sessions->renewals());
        self::assertNotEmpty(array_filter($this->recordedEvents(), static fn ($event): bool => $event instanceof ReauthenticationCompleted));
    }

    /**
     * The standalone path refuses a code bound to a reservation, leaving it
     * unconsumed, and `admit()` refuses to run with no transaction open.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheStandalonePathIsNotAnAdmission(): void
    {
        $start      = $this->start();
        $completion = $this->complete();
        $code       = (string) $completion->handoff?->code->reveal();
        $verifier   = (string) $start->verifier?->reveal();

        try {
            app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $this->connection->id, $code, $verifier, Clients::browser());
            self::fail('A session was admitted with no transaction open.');
        } catch (\LogicException $exception) {
            self::assertSame('A session is admitted inside the caller\'s transaction on the package\'s storage connection (decision D5).', $exception->getMessage());
        }

        try {
            app(HandoffRedemption::class)->redeem(Purpose::SIGN_IN, 'web', $this->connection->id, $code, $verifier, Clients::browser());
            self::fail('The standalone path activated a reservation.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString('admit()', $exception->getMessage());
        }

        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
        self::assertTrue($this->admit($completion, $start)->isRedeemed());
    }

    /**
     * A domain's withdrawal deletes its reservations and raises the links
     * version.
     *
     * @return void
     */
    public function testAWithdrawalDeletesTheDomainsReservations(): void
    {
        $this->start();
        $this->complete();

        $before = $this->connection->refresh()->links_version;

        self::assertSame(1, $before);

        app(DomainWithdrawal::class)->linkingWithdrawn($this->connection, $this->domain);

        self::assertSame(0, Link::query()->count());
        self::assertSame(2, $this->connection->refresh()->links_version);
    }

    /**
     * A linking version changed after validation reserves nothing.
     *
     * @return void
     */
    public function testALinkingVersionChangedAfterValidationReservesNothing(): void
    {
        config()->set('sso.applications.web.unlinked_handoffs', true);

        $this->start();

        $this->verifying->onComplete = function (): void {
            $this->connection->forceFill(['linking_version' => 1])->save();
        };

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Make an active link with verified domain provenance, through the machine.
     *
     * @return void
     */
    private function linkByDomain(): void
    {
        $start = $this->start();

        self::assertTrue($this->admit($this->complete(), $start)->isRedeemed());
    }

    /**
     * Make an active link with provisioning provenance.
     *
     * @return void
     */
    private function linkByProvisioning(): void
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
     * Put the machine back to where one case of a repeated test starts.
     *
     * @param  int  $index
     * @return void
     */
    private function resetFor(int $index): void
    {
        unset($index);

        Link::query()->delete();

        $this->matcher->match = LinkEmailMatch::exactlyOne($this->person);
        $this->scope->verdict = ScopeVerdict::WITHIN_TENANT;
        $this->domain->forceFill(['verification_generation' => 1, 'linking_suspended_at' => null])->save();
    }
}
