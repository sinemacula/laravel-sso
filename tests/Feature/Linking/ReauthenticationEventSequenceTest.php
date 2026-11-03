<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\Rules\ReauthenticationRules;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\LinkSuspended;
use SineMacula\Laravel\Sso\Events\ReauthenticationCompleted;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffEvents;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\Redemption\ReauthenticationBranch;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Pins what a `reauthenticate` flow reports, each sequence and every context
 * whole (SSO-5.10, SSO-9.5, SSO-10.1, SSO-10.2, SSO-10.4): started, verified,
 * issued, redeemed and completed; `ReauthenticationCompleted` only once the
 * transaction that wrote the renewal commits, and never when it rolls back
 * (SSO-10.5); a refusal at completion and at redemption; and that no context
 * carries a subject, an email, an authentication context, the code or the
 * verifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReauthenticationCompleted::class)]
#[CoversClass(ReauthenticationBranch::class)]
#[CoversClass(ReauthenticationRules::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(HandoffEvents::class)]
final class ReauthenticationEventSequenceTest extends LinkingTestCase
{
    /** @var string When every event occurs. */
    private const string OCCURRED_AT = '2026-11-01T09:30:00.000000Z';

    /** @var string The session the flows are started on. */
    private const string SESSION = 'session-1';

    /** @var string The provider's session id, which no context may carry. */
    private const string PROVIDER_SESSION = 'the-providers-session';

    /** @var string The provider's context class, which no context may carry. */
    private const string CONTEXT_CLASS = 'urn:the-providers-context-class';

    /**
     * The whole sequence, in order, every context the flow's, naming its
     * identity and session; both events of the redemption wait for the commit.
     *
     * @return void
     */
    public function testAReauthenticationReportsItsSequence(): void
    {
        $sessions = $this->sessionsFor($this->hold());

        $this->startRecordingEvents();

        $start      = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
        $completion = $this->complete();

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, HandoffIssued::class]);

        $this->connection->getConnection()->transaction(function () use ($completion, $start, $sessions): void {

            self::assertTrue($this->redeemInTransaction($completion, $start)->isAdmitted());
            self::assertSame(1, $sessions->renewals());

            $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, HandoffIssued::class]);
        });

        $this->assertEventSequence([
            AuthorizationRequestStarted::class,
            ResultVerified::class,
            HandoffIssued::class,
            HandoffRedeemed::class,
            ReauthenticationCompleted::class,
        ]);

        $context = $this->context($start);

        $this->assertContexts([$context, $context, $context, $context, $context]);
        $this->assertNoFailure();
    }

    /**
     * `ReauthenticationCompleted` is what its context says, and crosses a queue
     * as it is.
     *
     * @return void
     */
    public function testTheCompletedEventCrossesAQueueAsItIs(): void
    {
        $this->sessionsFor($this->hold());

        $start = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        self::assertTrue($this->admit($this->complete(), $start, Purpose::REAUTHENTICATE)->isAdmitted());

        $recorded = $this->recordedEvents();
        $event    = end($recorded);

        self::assertInstanceOf(ReauthenticationCompleted::class, $event);
        self::assertSame($event->context, $event->context());
        self::assertSame($this->context($start), $event->context()->toArray());

        $restored = unserialize(serialize($event));

        self::assertInstanceOf(ReauthenticationCompleted::class, $restored);
        self::assertSame($this->context($start), $restored->context()->toArray());
    }

    /**
     * Nothing a redemption reports survives the caller's rollback; a retry of
     * the whole transaction reports it once.
     *
     * @return void
     */
    public function testNothingIsReportedAfterTheCallersRollback(): void
    {
        $this->sessionsFor($this->hold());

        $start      = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
        $completion = $this->complete();

        $this->startRecordingEvents();
        $this->redeemThenRollBack($completion, $start, null);

        $this->assertNoEvents();

        self::assertTrue($this->admit($completion, $start, Purpose::REAUTHENTICATE)->isAdmitted());

        $this->assertEventSequence([HandoffRedeemed::class, ReauthenticationCompleted::class]);
    }

    /**
     * A refusal rolled back by the caller reports nothing either.
     *
     * @return void
     */
    public function testARefusalIsNotReportedAfterTheCallersRollback(): void
    {
        $sessions = $this->sessionsFor($this->hold());

        $start      = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
        $completion = $this->complete();

        $sessions->standing = SessionStanding::NOT_SIGNED_IN;

        $this->startRecordingEvents();
        $this->redeemThenRollBack($completion, $start, FailureReason::SESSION_INELIGIBLE);

        $this->assertNoEvents();
    }

    /**
     * An exception from the contract reports nothing at all.
     *
     * @return void
     */
    public function testAFailedRenewalReportsNothing(): void
    {
        $link = $this->hold();

        $this->app?->instance(ReauthenticationSessions::class, new class ($link->id) implements ReauthenticationSessions {
            /**
             * Constructor.
             *
             * @param  string  $linkId
             */
            public function __construct(

                /** The session's bound link. */
                private readonly string $linkId,
            ) {}

            /**
             * Signed in.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            #[\Override]
            public function standing(IdentityReference $identity, string $sessionId, SsoConnection $connection): SessionStanding
            {
                unset($identity, $sessionId, $connection);

                return SessionStanding::SIGNED_IN;
            }

            /**
             * Signed in through the bound link.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  string  $application
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  string  $linkId
             * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
             */
            #[\Override]
            public function lockedStanding(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection, string $linkId): SessionStanding
            {
                unset($identity, $sessionId, $application, $connection);

                return $linkId === $this->linkId ? SessionStanding::SIGNED_IN : SessionStanding::NOT_SIGNED_IN;
            }

            /**
             * Fail.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  string  $sessionId
             * @param  \Carbon\CarbonImmutable  $authenticatedAt
             * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function renewAuthentication(IdentityReference $identity, string $sessionId, CarbonImmutable $authenticatedAt, ?AcceptedEvidence $evidence): void
            {
                unset($identity, $sessionId, $authenticatedAt, $evidence);

                throw new \RuntimeException('The session store failed.');
            }
        });

        $start      = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
        $completion = $this->complete();

        $this->startRecordingEvents();

        try {
            $this->admit($completion, $start, Purpose::REAUTHENTICATE);
            self::fail('The contract\'s exception was swallowed.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The session store failed.', $exception->getMessage());
        }

        $this->assertNoEvents();
    }

    /**
     * A subject resolving to nobody is refused at completion: started,
     * verified, one failure of the callback flow, and no handoff.
     *
     * @return void
     */
    public function testARefusalAtCompletionReportsItsSequence(): void
    {
        $this->app?->instance(ReauthenticationSessions::class, new RecordingSessions('link'));

        $start = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        self::assertSame(FailureReason::IDENTITY_MISMATCH, $this->complete()->reason);

        $this->assertRefusedAtCompletion(FailureReason::IDENTITY_MISMATCH, $start);
    }

    /**
     * A subject linked to another identity is refused at completion, and the
     * context names only the flow's identity.
     *
     * @return void
     */
    public function testARefusalAtCompletionNamesOnlyTheFlowsIdentity(): void
    {
        $this->app?->instance(ReauthenticationSessions::class, new RecordingSessions('link'));
        $this->hold(new IdentityReference('App\Models\User', '8'));
        $this->startRecordingEvents();

        $start = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        self::assertSame(FailureReason::IDENTITY_MISMATCH, $this->complete()->reason);

        $this->assertRefusedAtCompletion(FailureReason::IDENTITY_MISMATCH, $start);
    }

    /**
     * A link already suspended is refused at completion; the suspension was
     * reported when it was latched, and is not reported again.
     *
     * @return void
     */
    public function testASuspendedLinkAtCompletionReportsItsSequence(): void
    {
        $link = $this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN);

        $this->sessionsFor($link);

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        self::assertSame(FailureReason::LINK_SUSPENDED, $this->complete()->reason);

        $this->startRecordingEvents();

        $start = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        self::assertSame(FailureReason::LINK_SUSPENDED, $this->complete()->reason);

        $this->assertRefusedAtCompletion(FailureReason::LINK_SUSPENDED, $start);
    }

    /**
     * A response with no authentication time from a driver that lets one pass
     * is refused once verified, like any other refusal at completion.
     *
     * @return void
     */
    public function testNoAuthenticationTimeAtCompletionReportsItsSequence(): void
    {
        $this->sessionsFor($this->hold());
        $this->startRecordingEvents();

        $this->verifying->claims = new VerifiedClaims(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT, null, ['mail' => self::EMAIL], new AuthenticationContext);

        $start = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);

        self::assertSame(FailureReason::AUTHENTICATION_EXPIRED, $this->complete()->reason);

        $this->assertRefusedAtCompletion(FailureReason::AUTHENTICATION_EXPIRED, $start);
    }

    /**
     * Rows of what comes to be wrong between completion and redemption, and the
     * reason it is refused for.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideRefusalsAtRedemption(): iterable
    {
        yield 'the session revoked' => ['session', FailureReason::SESSION_INELIGIBLE];
        yield 'the link gone' => ['link', FailureReason::IDENTITY_MISMATCH];
    }

    /**
     * A refusal at redemption reports exactly one failure of the redemption
     * flow after what completion reported, naming the flow's identity and
     * session, and no redemption or completion.
     *
     * @param  string  $change
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefusalsAtRedemption')]
    public function testARefusalAtRedemptionReportsExactlyOneFailure(string $change, FailureReason $reason): void
    {
        $link     = $this->hold();
        $sessions = $this->sessionsFor($link);

        $this->startRecordingEvents();

        $start      = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
        $completion = $this->complete();

        if ($change === 'session') {
            $sessions->standing = SessionStanding::NOT_SIGNED_IN;
        } else {
            Link::query()->whereKey($link->id)->delete();
        }

        self::assertSame($reason, $this->admit($completion, $start, Purpose::REAUTHENTICATE)->reason);

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, HandoffIssued::class, FlowFailed::class]);

        $context = $this->context($start);

        $this->assertContexts([$context, $context, $context, $context]);
        $this->assertExactlyOneFailure(Flow::REDEMPTION, $reason);
    }

    /**
     * A link found suspended at redemption reports the suspension as its
     * holder's, and one failure as the flow's.
     *
     * @return void
     */
    public function testASuspensionAtRedemptionReportsTheSuspensionThenTheFailure(): void
    {
        $this->sessionsFor($this->hold($this->person, LinkOrigin::VERIFIED_DOMAIN));

        $start      = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
        $completion = $this->complete();

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        $this->startRecordingEvents();

        self::assertSame(FailureReason::LINK_SUSPENDED, $this->admit($completion, $start, Purpose::REAUTHENTICATE)->reason);

        $this->assertEventSequence([LinkSuspended::class, FlowFailed::class]);
        $this->assertContexts([$this->suspensionContext(), $this->context($start)]);
        $this->assertExactlyOneFailure(Flow::REDEMPTION, FailureReason::LINK_SUSPENDED);
    }

    /**
     * A replay reports one failure and renews nothing more; no second
     * completion.
     *
     * @return void
     */
    public function testAReplayReportsOneFailure(): void
    {
        $this->sessionsFor($this->hold());

        $start      = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
        $completion = $this->complete();

        self::assertTrue($this->admit($completion, $start, Purpose::REAUTHENTICATE)->isAdmitted());

        $this->startRecordingEvents();

        self::assertSame(FailureReason::REPLAYED, $this->admit($completion, $start, Purpose::REAUTHENTICATE)->reason);

        $this->assertEventSequence([FlowFailed::class]);
        $this->assertContexts([$this->context($start)]);
    }

    /**
     * No event of a `reauthenticate` flow, serialised whole or read through its
     * context, carries the subject, the email, the authentication context, the
     * code or the verifier.
     *
     * @return void
     */
    public function testNoEventCarriesASecretOrTheAuthenticationContext(): void
    {
        $this->sessionsFor($this->hold());
        $this->startRecordingEvents();

        $this->verifying->claims = new VerifiedClaims(
            VerifyingDriver::ISSUER,
            VerifyingDriver::SUBJECT,
            null,
            ['mail' => self::EMAIL],
            new AuthenticationContext($this->clock->now()->subSeconds(7), ['pwd'], self::CONTEXT_CLASS, self::PROVIDER_SESSION),
            new LinkingEmail(self::EMAIL, LinkingEmailSource::ID_TOKEN),
        );

        $start      = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
        $completion = $this->complete();
        $code       = (string) $completion->handoff?->code->reveal();
        $verifier   = (string) $start->verifier?->reveal();

        self::assertTrue($this->admit($completion, $start, Purpose::REAUTHENTICATE)->isAdmitted());

        $events = $this->recordedEvents();

        self::assertCount(5, $events);

        $reported = (string) json_encode(array_map(static fn (SsoEvent $event): array => $event->context()->toArray(), $events)) . serialize($events);

        foreach ([trim(VerifyingDriver::SUBJECT), self::EMAIL, self::CONTEXT_CLASS, self::PROVIDER_SESSION, '09:29:53', $code, $verifier] as $secret) {
            self::assertStringNotContainsString($secret, $reported);
        }
    }

    /**
     * Make a link of the subject for the identity, through the store.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function hold(?IdentityReference $identity = null, LinkOrigin $origin = LinkOrigin::PROVISIONING): Link
    {
        $creation = app(LinkStore::class)->create($this->connection, new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT), $identity ?? $this->person, $origin);

        self::assertTrue($creation->isCreated());

        return Link::query()->whereKey($creation->link?->id)->sole();
    }

    /**
     * Bind the recording contract, with one session bound to the link.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @return \Tests\Fixtures\Linking\RecordingSessions
     */
    private function sessionsFor(Link $link): RecordingSessions
    {
        $sessions = new RecordingSessions($link->id);

        $this->app?->instance(ReauthenticationSessions::class, $sessions);

        return $sessions;
    }

    /**
     * Redeem the code inside the transaction already open.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $completion
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function redeemInTransaction(CompletionResult $completion, StartResult $start): RedemptionResult
    {
        $code     = (string) $completion->handoff?->code->reveal();
        $verifier = (string) $start->verifier?->reveal();

        return app(HandoffRedemption::class)->admit(Purpose::REAUTHENTICATE, 'web', $this->connection->id, $code, $verifier);
    }

    /**
     * Redeem the code inside a transaction that then rolls back, and assert
     * what the redemption answered inside it.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $completion
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    private function redeemThenRollBack(CompletionResult $completion, StartResult $start, ?FailureReason $reason): void
    {
        try {
            DB::connection(StorageConnection::name())->transaction(function () use ($completion, $start, $reason): void {

                self::assertSame($reason, $this->redeemInTransaction($completion, $start)->reason);

                throw new \RuntimeException('The caller rolled back.');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('The caller rolled back.', $exception->getMessage());
        }
    }

    /**
     * Assert the flow was verified and refused at completion for the reason,
     * each event with the whole context of the flow.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return void
     */
    private function assertRefusedAtCompletion(FailureReason $reason, StartResult $start): void
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
     * The whole context of an event of the flow, naming the flow's identity and
     * session.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return array<string, ?string>
     */
    private function context(StartResult $start): array
    {
        return [
            'occurred_at'                 => self::OCCURRED_AT,
            'ip'                          => '203.0.113.7',
            'user_agent'                  => 'Symfony',
            'connection_id'               => $this->connection->id,
            'connection_tenant_id'        => 'tenant-1',
            'protocol'                    => VerifyingDriver::NAME,
            'application'                 => 'web',
            'purpose'                     => 'reauthenticate',
            'request_reference'           => $start->reference?->value,
            'identity_morph_class'        => $this->person->type,
            'identity_id'                 => $this->person->id,
            'acting_identity_morph_class' => null,
            'acting_identity_id'          => null,
            'principal_morph_class'       => null,
            'principal_id'                => null,
            'tenant_id'                   => null,
            'session_id'                  => self::SESSION,
            'method'                      => null,
        ];
    }

    /**
     * The whole context of a link's suspension: the connection and the holder,
     * and nothing of any flow.
     *
     * @return array<string, ?string>
     */
    private function suspensionContext(): array
    {
        return [
            'occurred_at'                 => self::OCCURRED_AT,
            'ip'                          => '203.0.113.7',
            'user_agent'                  => 'Symfony',
            'connection_id'               => $this->connection->id,
            'connection_tenant_id'        => 'tenant-1',
            'protocol'                    => VerifyingDriver::NAME,
            'application'                 => null,
            'purpose'                     => null,
            'request_reference'           => null,
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
}
