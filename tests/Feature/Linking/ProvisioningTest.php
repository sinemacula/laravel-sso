<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn;
use SineMacula\Laravel\Sso\Completion\CompletionLocks;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\ProvisioningOffer;
use SineMacula\Laravel\Sso\Completion\ResultBuilder;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Completion\Stages\DecideUnlinked;
use SineMacula\Laravel\Sso\Completion\Stages\Provisioning;
use SineMacula\Laravel\Sso\Completion\Stages\ValidateResponse;
use SineMacula\Laravel\Sso\Completion\VerifiedDeadlines;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkCreation;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\TransitionReceipt;
use SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningResult;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use Tests\Concerns\DumpsValues;
use Tests\Concerns\RecordsLockOrder;
use Tests\Concerns\UsesEnforcement;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * The provisioning helper and its grant, through the public completion
 * (SSO-8.6, `docs/design/linking.md`): what a link made through them looks like
 * and how the final continuation resolves it; every way a grant is refused; a
 * listener's exception, its open transaction and its rollback; authority
 * withdrawn during the listener; the deadline at, one second before and one
 * after, at the helper and at the final continuation; subjects held and limits
 * reached; which results are never offered; and the lock order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(CompletionLocks::class)]
#[CoversClass(ProvisioningHelper::class)]
#[CoversClass(ProvisioningResult::class)]
#[CoversClass(ProvisioningStatus::class)]
#[CoversClass(ProvisioningGrant::class)]
#[CoversClass(ProvisioningOffer::class)]
#[CoversClass(Provisioning::class)]
#[CoversClass(DecideUnlinked::class)]
#[CoversClass(ResultUnlinked::class)]
final class ProvisioningTest extends LinkingTestCase
{
    use DumpsValues, RecordsLockOrder, UsesEnforcement;

    /** @var string The application's table of identities, which the listener writes to. */
    private const string IDENTITIES = 'provisioned_identities';

    /** @var int The default stale limit of what was fetched for a connection, in seconds. */
    private const int STALE_LIMIT = 2592000;

    /** @var int The default longest a verified response may keep finishing, in seconds. */
    private const int MAX_AGE = 120;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference Another identity than the one the listener provisions. */
    private IdentityReference $other;

    /** @var list<\SineMacula\Laravel\Sso\Provisioning\ProvisioningResult> What the helper answered, in order. */
    private array $answers = [];

    /** @var int How many times the result was offered. */
    private int $offered = 0;

    /**
     * Make the result unmatched by any verified domain, so it reaches the
     * provisioning boundary; create the application's table of identities and
     * the enforcement table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->matcher->match = LinkEmailMatch::none();
        $this->other          = new IdentityReference('App\Models\User', '8');

        $this->createEnforcementTable();

        Schema::connection(StorageConnection::name())->create(self::IDENTITIES, static function (Blueprint $table): void {
            $table->string('id')->primary();
        });

        Event::listen(ResultUnlinked::class, function (): void {
            $this->offered++;
        });
    }

    /**
     * Drop the application's table of identities and the enforcement table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::connection(StorageConnection::name())->dropIfExists(self::IDENTITIES);

        $this->dropEnforcementTable();

        parent::tearDown();
    }

    /**
     * The provisioning stage stops only a `sign_in` it knows to be unlinked: a
     * state with no resolution, or no consumed request, goes on.
     *
     * @return void
     */
    public function testTheStageStopsOnlyWhatItKnowsIsUnlinked(): void
    {
        $arrived  = CompletionState::arrived($this->connection->id, new CompletionRequest('GET', '', []));
        $consumed = new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::fromString(str_repeat('r', 32)), $this->clock->now());
        $request  = new AuthorizationRequest;
        $signIn   = $arrived->withAuthorizationRequest($request, $consumed, Application::fromSettings('web', ['redirect_uri' => 'https://app.example.com/sso']));
        $stage    = new Provisioning;

        self::assertTrue($stage->run($arrived)->isProceeding(), 'nothing known');
        self::assertTrue($stage->run($signIn)->isProceeding(), 'no resolution');
        self::assertTrue($stage->run($arrived->withResolution(LinkResolution::absent()))->isProceeding(), 'no consumed request');
        self::assertTrue($stage->run($signIn->withResolution(LinkResolution::absent()))->isProvisioning(), 'known unlinked');
    }

    /**
     * The helper makes an active link with provisioning as its origin, holding
     * the subject byte for byte; raises the links version; and answers its
     * summary. The final continuation resolves it anew, and issues the handoff
     * bound to the new link's id, which redeems to the new identity.
     *
     * @return void
     */
    public function testTheHelperMakesTheLinkAndTheFinalContinuationResolvesIt(): void
    {
        $start = $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {
            self::assertSame(ProvisioningStatus::CREATED, $this->provision($event)->status);
        });

        $completion = $this->complete();
        $link       = Link::query()->sole();
        $answer     = $this->answers[0];

        self::assertTrue($completion->isCompleted());
        self::assertSame(1, $this->offered);
        self::assertTrue($answer->isCreated());
        self::assertFalse($answer->isRefused());
        self::assertNull($answer->reason());
        self::assertSame($link->id, $answer->link?->id);
        self::assertSame(['status' => 'created', 'link' => $answer->link->jsonSerialize(), 'reason' => null], $answer->jsonSerialize());
        self::assertSame(LinkState::ACTIVE, $link->state);
        self::assertSame(LinkOrigin::PROVISIONING, $link->provenance);
        self::assertFalse($link->domain_provenance);
        self::assertSame(VerifyingDriver::SUBJECT, $link->subject);
        self::assertSame(VerifyingDriver::ISSUER, $link->issuer);
        self::assertSame([$this->person->type, $this->person->id], [$link->identity_type, $link->identity_id]);
        self::assertSame(1, $this->connection->refresh()->links_version);
        self::assertNotNull(AuthorizationRequest::query()->sole()->completed_at);

        $redeemed = $this->admit($completion, $start);

        self::assertSame($this->person->id, $redeemed->linkedIdentity?->id);
        self::assertSame($link->id, $redeemed->linkId);
    }

    /**
     * Each status is named, carries its failure reason, and reads as created or
     * refused.
     *
     * @return void
     */
    public function testEachStatusCarriesItsFailureReason(): void
    {
        $expected = [
            'created'                => null,
            'grant_invalid'          => 'provisioning_grant_invalid',
            'grant_wrong_result'     => 'provisioning_grant_invalid',
            'request_unavailable'    => 'connection_unavailable',
            'expired'                => 'request_expired',
            'subject_already_linked' => 'subject_already_linked',
            'link_limit_reached'     => 'link_limit_reached',
        ];

        $actual = [];

        foreach (ProvisioningStatus::cases() as $status) {
            $actual[$status->value] = $status->reason()?->value;
        }

        self::assertSame($expected, $actual);
    }

    /**
     * Each refusal is a value with its status, its reason and no link.
     *
     * @return void
     */
    public function testEachRefusalIsAValue(): void
    {
        $refusals = [
            ['grant_invalid', 'provisioning_grant_invalid', ProvisioningResult::grantInvalid()],
            ['request_unavailable', 'connection_unavailable', ProvisioningResult::requestUnavailable()],
            ['expired', 'request_expired', ProvisioningResult::expired()],
            ['subject_already_linked', 'subject_already_linked', ProvisioningResult::subjectAlreadyLinked()],
            ['subject_already_linked', 'subject_already_linked', ProvisioningResult::fromCreation(LinkCreation::subjectAlreadyLinked())],
            ['link_limit_reached', 'link_limit_reached', ProvisioningResult::fromCreation(LinkCreation::linkLimitReached())],
        ];

        foreach ($refusals as [$status, $reason, $result]) {
            self::assertTrue($result->isRefused(), $status);
            self::assertFalse($result->isCreated(), $status);
            self::assertNull($result->link, $status);
            self::assertSame(['status' => $status, 'link' => null, 'reason' => $reason], $result->jsonSerialize());
        }
    }

    /**
     * What makes another result object carrying the same fields.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Sso\Results\VerifiedResult): \SineMacula\Laravel\Sso\Results\VerifiedResult}>
     */
    public static function provideCopies(): iterable
    {
        yield 'its public constructor arguments' => [static fn (VerifiedResult $result): VerifiedResult => new VerifiedResult(
            $result->issuer,
            $result->subject,
            $result->nameIdFormat,
            $result->connectionId,
            $result->tenantId,
            $result->protocol,
            $result->application,
            $result->purpose,
            $result->requestReference,
            $result->attributes,
            $result->emailDomainVerified,
            $result->authenticationContext,
            $result->linkingEmail,
            $result->assertedEmail,
        )];

        yield 'what it stored' => [static fn (VerifiedResult $result): VerifiedResult => VerifiedResult::restore($result->toArray())];

        yield 'a clone' => [static fn (VerifiedResult $result): VerifiedResult => clone $result];

        yield 'a round trip through serialisation' => [static fn (VerifiedResult $result): VerifiedResult => self::roundTrip($result)];
    }

    /**
     * Another result object carrying identical fields is refused, whichever way
     * it was made, writes nothing, and spends the grant's one use: the exact
     * result then gets no link either, and the completion ends unlinked.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Results\VerifiedResult): \SineMacula\Laravel\Sso\Results\VerifiedResult  $copy
     * @return void
     */
    #[DataProvider('provideCopies')]
    public function testAResultWithIdenticalFieldsIsRefused(\Closure $copy): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event) use ($copy): void {

            $copied = $copy($event->result);

            self::assertNotSame($event->result, $copied);
            self::assertSame($event->result->toArray(), $copied->toArray());

            $this->answers[] = app(ProvisioningHelper::class)->link($event->grant, $copied, $this->person);

            self::assertFalse($event->grant->isUsable());

            $this->provision($event);
        });

        $completion = $this->complete();

        self::assertSame([ProvisioningStatus::GRANT_WRONG_RESULT, ProvisioningStatus::GRANT_INVALID], $this->statuses());
        self::assertSame(FailureReason::PROVISIONING_GRANT_INVALID, $this->answers[0]->reason());
        self::assertSame(0, Link::query()->count());
        self::assertSame(0, $this->connection->refresh()->links_version);
        self::assertSame(FailureReason::UNLINKED, $completion->reason);
    }

    /**
     * A grant of the exact result that no dispatch issued is refused during the
     * dispatch and after it, and spends nothing of the real one.
     *
     * @return void
     */
    public function testAGrantNoDispatchIssuedIsRefused(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {

            $forged = ProvisioningGrant::issue($event->result, AuthorizationRequest::query()->sole()->id, $this->clock->now()->addHour());

            self::assertTrue($forged->isUsable());

            $this->answers[] = app(ProvisioningHelper::class)->link($forged, $event->result, $this->other);

            self::assertSame(0, Link::query()->count());
            self::assertTrue($event->grant->isUsable());

            $this->provision($event);
        });

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame([ProvisioningStatus::GRANT_INVALID, ProvisioningStatus::CREATED], $this->statuses());
        self::assertSame($this->person->id, Link::query()->sole()->identity_id);
    }

    /**
     * A grant used twice gets one link, for the identity it was used for first.
     *
     * @return void
     */
    public function testAGrantUsedTwiceLinksOnce(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {
            $this->provision($event);
            $this->provision($event, $this->other);
        });

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame([ProvisioningStatus::CREATED, ProvisioningStatus::GRANT_INVALID], $this->statuses());
        self::assertSame($this->person->id, Link::query()->sole()->identity_id);
    }

    /**
     * A second listener shares the first's one use.
     *
     * @return void
     */
    public function testASecondListenerGetsNoSecondUse(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {
            $this->provision($event);
        });

        $this->onOffer(function (ResultUnlinked $event): void {
            $this->provision($event, $this->other);
        });

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame(1, $this->offered);
        self::assertSame([ProvisioningStatus::CREATED, ProvisioningStatus::GRANT_INVALID], $this->statuses());
        self::assertSame($this->person->id, Link::query()->sole()->identity_id);
    }

    /**
     * A call made reentrantly, from inside the helper's own work (a link limit
     * contract, here), gets no use, and leaves the outer call to finish.
     *
     * @return void
     */
    public function testAReentrantCallGetsNoUse(): void
    {
        $this->start();

        $limit = new class implements LinkLimit {
            /** @var ?\Closure(): void What runs as the limit is next asked. */
            public ?\Closure $onAsked = null;

            /**
             * Run what was set, once, and answer one.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return int
             */
            #[\Override]
            public function maxLinks(IdentityReference $identity, SsoConnection $connection): int
            {
                unset($identity, $connection);

                $onAsked       = $this->onAsked;
                $this->onAsked = null;

                if ($onAsked !== null) {
                    $onAsked();
                }

                return 1;
            }
        };

        $this->app?->instance(LinkLimit::class, $limit);

        $this->onOffer(function (ResultUnlinked $event) use ($limit): void {

            $limit->onAsked = function () use ($event): void {
                $this->provision($event, $this->other);
            };

            $this->provision($event);
        });

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame([ProvisioningStatus::GRANT_INVALID, ProvisioningStatus::CREATED], $this->statuses());
        self::assertSame($this->person->id, Link::query()->sole()->identity_id);
    }

    /**
     * A refused attempt spends the grant: it cannot be tried again for another
     * identity.
     *
     * @return void
     */
    public function testARefusedAttemptCannotBeRepeatedForAnotherIdentity(): void
    {
        $this->holdTheLimitOf($this->person);
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {
            $this->provision($event);
            $this->provision($event, $this->other);
        });

        $completion = $this->complete();

        self::assertSame([ProvisioningStatus::LINK_LIMIT_REACHED, ProvisioningStatus::GRANT_INVALID], $this->statuses());
        self::assertSame(FailureReason::LINK_LIMIT_REACHED, $this->answers[0]->reason());
        self::assertSame(1, Link::query()->count());
        self::assertSame(FailureReason::UNLINKED, $completion->reason);
    }

    /**
     * A grant kept after its dispatch returned opens nothing, while the request
     * is finished; the exact result is not enough.
     *
     * @return void
     */
    public function testAGrantKeptAfterTheDispatchReturnedIsRefused(): void
    {
        $this->start();

        $kept = null;

        $this->onOffer(static function (ResultUnlinked $event) use (&$kept): void {
            $kept = $event;
        });

        self::assertSame(FailureReason::UNLINKED, $this->complete()->reason);
        self::assertInstanceOf(ResultUnlinked::class, $kept);
        self::assertFalse($kept->grant->isUsable());
        self::assertSame(ProvisioningStatus::GRANT_INVALID, $this->provision($kept)->status);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * A grant kept after a listener threw opens nothing, though the request is
     * still consumed, unfinished and within its deadline: only the dispatch
     * gave it authority.
     *
     * @return void
     */
    public function testAGrantKeptAfterAListenerThrewIsRefused(): void
    {
        $this->start();

        $kept = null;

        $this->onOffer(static function (ResultUnlinked $event) use (&$kept): void {

            $kept = $event;

            throw new \RuntimeException('The listener failed.');
        });

        $this->assertListenerFailure('The listener failed.');

        self::assertInstanceOf(ResultUnlinked::class, $kept);
        self::assertNull(AuthorizationRequest::query()->sole()->completed_at);
        self::assertSame(ProvisioningStatus::GRANT_INVALID, $this->provision($kept)->status);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Neither the grant nor the event can be cloned into a second use,
     * serialised or unserialised, and no dump, export, array cast or JSON of
     * either shows the result, the subject, an attribute or the request's id.
     *
     * @return void
     */
    public function testTheGrantAndTheEventShowNothingAndCannotBeCopied(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {

            $grant = $event->grant;
            $class = ProvisioningGrant::class;

            self::assertSame('A provisioning grant cannot be cloned.', self::refusalOf(static fn (): ProvisioningGrant => clone $grant));
            self::assertSame('A provisioning grant cannot be serialised.', self::refusalOf(static fn (): string => serialize($grant)));
            self::assertSame('A provisioning grant cannot be unserialised.', self::refusalOf(static fn (): mixed => unserialize(self::emptyPayload($class))));
            self::assertSame(
                'The unlinked-result event cannot be serialised: a queued listener is too late (SSO-8.6).',
                self::refusalOf(static fn (): string => serialize($event)),
            );
            self::assertSame('The unlinked-result event cannot be unserialised.', self::refusalOf(static fn (): mixed => unserialize(self::emptyPayload($event::class))));

            $copy = clone $event;

            self::assertSame($grant, $copy->grant);
            self::assertSame($event->result, $copy->result);
            self::assertSame('{"usable":true}', json_encode($grant));
            self::assertSame(['usable' => true], $grant->__debugInfo());
            self::assertSame((string) json_encode(['context' => $event->context->toArray()]), json_encode($event));

            foreach ([$grant, $event, (array) $grant, (array) $event] as $value) {
                foreach (self::dumps($value) as $how => $dump) {
                    $this->assertShowsNothingOfTheResult($dump, $how);
                }
            }
        });

        self::assertSame(FailureReason::UNLINKED, $this->complete()->reason);
        self::assertSame(1, $this->offered);
    }

    /**
     * A queued listener is too late and fails loudly: queuing the event refuses
     * to serialise it, the completion ends as a server error, and nothing is
     * issued.
     *
     * @return void
     */
    public function testAQueuedListenerFailsLoudly(): void
    {
        config()->set('queue.default', 'sync');

        $listener = new class implements ShouldQueue {
            /**
             * Never reached: the event never reaches the queue.
             *
             * @param  \SineMacula\Laravel\Sso\Events\ResultUnlinked  $event
             * @return void
             *
             * @throws \RuntimeException
             */
            public function handle(ResultUnlinked $event): void
            {
                unset($event);

                throw new \RuntimeException('A queued listener ran.');
            }
        };

        Event::listen(ResultUnlinked::class, [$listener::class, 'handle']);

        $this->start();

        try {
            $this->complete();

            self::fail('The event reached the queue.');
        } catch (\Throwable $exception) {
            self::assertSame('The unlinked-result event cannot be serialised: a queued listener is too late (SSO-8.6).', self::rootCause($exception)->getMessage());
            self::assertInstanceOf(\LogicException::class, self::rootCause($exception));
        }

        $this->assertConsumedAndUnfinished();
    }

    /**
     * A listener throwing before it makes anything ends the completion as a
     * server error: the request stays consumed and unfinished, no code is kept,
     * and a replay of the response is `request_unknown`, offering nothing.
     *
     * @return void
     */
    public function testAListenerThrowingBeforeItLinksEndsTheCompletion(): void
    {
        $this->start();

        $this->onOffer(static function (): void {
            throw new \RuntimeException('Before the link.');
        });

        $this->assertListenerFailure('Before the link.');
        $this->assertConsumedAndUnfinished();
        self::assertSame(0, Link::query()->count());

        $replay = $this->complete();

        self::assertTrue($replay->isRejected());
        self::assertSame(FailureReason::REQUEST_UNKNOWN, $replay->reason);
        self::assertSame(1, $this->offered);
        $this->assertConsumedAndUnfinished();
    }

    /**
     * A listener throwing after it committed a link ends the completion too;
     * the link stays made, nothing resumes it, and only a new flow resolves it,
     * offering nothing.
     *
     * @return void
     */
    public function testAListenerThrowingAfterItLinkedLeavesTheLink(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {

            $this->provision($event);

            throw new \RuntimeException('After the link.');
        });

        $this->assertListenerFailure('After the link.');
        $this->assertConsumedAndUnfinished();
        self::assertSame(LinkOrigin::PROVISIONING, Link::query()->sole()->provenance);

        $replay = $this->complete();

        self::assertTrue($replay->isRejected());
        self::assertSame(FailureReason::REQUEST_UNKNOWN, $replay->reason);
        self::assertSame(1, $this->offered);

        Event::forget(ResultUnlinked::class);
        AuthorizationRequest::query()->delete();

        $start = $this->start();

        self::assertSame($this->person->id, $this->admit($this->complete(), $start)->linkedIdentity?->id);
    }

    /**
     * A listener that leaves its transaction open, holding a link, is a
     * `LogicException`: what it opened rolls back, the grant closes, and the
     * link's event never comes.
     *
     * @return void
     */
    public function testAListenerLeavingATransactionOpenLosesWhatItMade(): void
    {
        $this->start();

        $kept = null;

        $this->onOffer(function (ResultUnlinked $event) use (&$kept): void {

            $kept = $event;

            DB::connection(StorageConnection::name())->beginTransaction();

            $this->writeIdentity();
            $this->provision($event);
        });

        try {
            $this->complete();

            self::fail('The completion went on.');
        } catch (\LogicException $exception) {
            self::assertSame('A provisioning listener must commit or roll back its transaction before it returns (SSO-8.6).', $exception->getMessage());
        }

        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertSame([ProvisioningStatus::CREATED], $this->statuses());
        self::assertSame(0, Link::query()->count());
        self::assertSame(0, $this->identities());
        self::assertSame(0, $this->connection->refresh()->links_version);
        self::assertFalse($this->hasSeenLinkCreated());
        self::assertInstanceOf(ResultUnlinked::class, $kept);
        self::assertFalse($kept->grant->isUsable());
        $this->assertConsumedAndUnfinished();
    }

    /**
     * A listener's exception inside its transaction rolls that back with the
     * exception: neither the identity nor the link stays, and nothing leaves a
     * level open.
     *
     * @return void
     */
    public function testAListenerThrowingInsideItsTransactionKeepsNothing(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {
            DB::connection(StorageConnection::name())->transaction(function () use ($event): void {

                $this->writeIdentity();
                $this->provision($event);

                throw new \RuntimeException('Inside the transaction.');
            });
        });

        $this->assertListenerFailure('Inside the transaction.');

        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertSame(0, Link::query()->count());
        self::assertSame(0, $this->identities());
        self::assertFalse($this->hasSeenLinkCreated());
    }

    /**
     * Identity, membership and link commit together in the listener's
     * transaction, and the link's event waits for that outer commit.
     *
     * @return void
     */
    public function testTheListenersTransactionCommitsTheIdentityAndTheLinkTogether(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {

            $database = DB::connection(StorageConnection::name());

            $database->beginTransaction();

            $this->writeIdentity();

            self::assertSame(ProvisioningStatus::CREATED, $this->provision($event)->status);
            self::assertSame(1, $database->transactionLevel());
            self::assertFalse($this->hasSeenLinkCreated());

            $database->commit();

            self::assertTrue($this->hasSeenLinkCreated());
        });

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame(1, $this->identities());
        self::assertSame(1, Link::query()->count());
    }

    /**
     * A listener rolling back on a refusal keeps no identity, and the
     * completion ends unlinked; a refusal itself raises nothing.
     *
     * @return void
     */
    public function testAListenerRollsItsIdentityBackOnARefusal(): void
    {
        $this->holdTheLimitOf($this->person);
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {

            $database = DB::connection(StorageConnection::name());
            $before   = $this->connection->refresh()->links_version;

            $database->beginTransaction();

            $this->writeIdentity();

            self::assertTrue($this->provision($event)->isRefused());
            self::assertSame($before, $this->connection->refresh()->links_version);

            $database->rollBack();
        });

        self::assertSame(FailureReason::UNLINKED, $this->complete()->reason);
        self::assertSame(0, $this->identities());
        self::assertSame(1, Link::query()->count());
    }

    /**
     * A link the listener rolls back, the helper having made it, never reports
     * and never resolves.
     *
     * @return void
     */
    public function testALinkRolledBackByTheListenerLeavesTheResultUnlinked(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {

            $database = DB::connection(StorageConnection::name());

            $database->beginTransaction();

            self::assertTrue($this->provision($event)->isCreated());

            $database->rollBack();
        });

        self::assertSame(FailureReason::UNLINKED, $this->complete()->reason);
        self::assertFalse($this->hasSeenLinkCreated());
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Each way the request's or the connection's authority can go during the
     * listener, and what the final continuation answers: `[how, reason]`.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideWithdrawals(): iterable
    {
        yield 'the request voided' => ['voided', FailureReason::CONNECTION_UNAVAILABLE];
        yield 'the request gone' => ['request_gone', FailureReason::CONNECTION_UNAVAILABLE];
        yield 'the trust changed' => ['trust', FailureReason::CONNECTION_UNAVAILABLE];
        yield 'the connection disabled' => ['disabled', FailureReason::CONNECTION_UNAVAILABLE];
        yield 'the connection gone' => ['connection_gone', FailureReason::CONNECTION_UNAVAILABLE];
        yield 'the metadata expired' => ['metadata_expired', FailureReason::METADATA_EXPIRED];
    }

    /**
     * Authority withdrawn during the listener refuses the helper, which writes
     * nothing, as `request_unavailable`, and the final continuation refuses in
     * its turn.
     *
     * @param  string  $how
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $final
     * @return void
     */
    #[DataProvider('provideWithdrawals')]
    public function testAuthorityWithdrawnDuringTheListenerRefusesTheHelper(string $how, FailureReason $final): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event) use ($how): void {
            $this->withdraw($how);
            $this->provision($event);
        });

        $completion = $this->complete();

        self::assertSame([ProvisioningStatus::REQUEST_UNAVAILABLE], $this->statuses());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->answers[0]->reason());
        self::assertSame(0, Link::query()->count());
        self::assertSame($final, $completion->reason);
        self::assertNull($completion->handoff);
        $this->assertExactlyOneFailure(Flow::CALLBACK, $final);
    }

    /**
     * The same withdrawal with the listener having made nothing is refused by
     * the final continuation alone.
     *
     * @param  string  $how
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $final
     * @return void
     */
    #[DataProvider('provideWithdrawals')]
    public function testAuthorityWithdrawnWithNothingMadeRefusesTheFinalContinuation(string $how, FailureReason $final): void
    {
        config()->set('sso.applications.web.unlinked_handoffs', true);

        $this->start();

        $this->onOffer(function () use ($how): void {
            $this->withdraw($how);
        });

        $completion = $this->complete();

        self::assertSame($final, $completion->reason);
        self::assertNull($completion->handoff);
        self::assertSame(0, HandoffCode::query()->count());
        $this->assertExactlyOneFailure(Flow::CALLBACK, $final);
    }

    /**
     * Rows of `[whether the listener provisions, whether what it made stands]`:
     * the final continuation refuses either way, and what the helper committed
     * survives.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideListeners(): iterable
    {
        yield 'the helper linked the person first' => [true];
        yield 'the listener made nothing' => [false];
    }

    /**
     * A rule tightened while the listener runs is judged by the final
     * continuation: no code is issued, and a link the helper committed stands.
     *
     * @param  bool  $provisions
     * @return void
     */
    #[DataProvider('provideListeners')]
    public function testAnEnforcementTightenedDuringTheListenerRefusesTheFinish(bool $provisions): void
    {
        config()->set('sso.features.enforcement', true);
        config()->set('sso.applications.web.unlinked_handoffs', true);

        $other = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);

        $this->start();

        $this->onOffer(function (ResultUnlinked $event) use ($provisions, $other): void {

            if ($provisions) {
                self::assertTrue($this->provision($event)->isCreated());
            }

            // The guard row the completion inserted is unconfigured until it
            // holds a version
            TenantEnforcement::query()->where('tenant_id', 'tenant-1')->sole()->forceFill([
                'enabled'        => true,
                'connection_ids' => [$other->id],
                'version'        => '01tighteneddurngthelistenr',
                'changed_at'     => $this->clock->now(),
            ])->save();
        });

        $completion = $this->complete();

        self::assertSame(FailureReason::ENFORCEMENT_UNSATISFIED, $completion->reason);
        self::assertNull($completion->handoff);
        self::assertSame(0, HandoffCode::query()->count());
        self::assertSame($provisions ? 1 : 0, Link::query()->count());
        self::assertNotNull(AuthorizationRequest::query()->sole()->completed_at);
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::ENFORCEMENT_UNSATISFIED);
    }

    /**
     * An application policy that stops allowing the application while the
     * listener runs is asked by the final continuation: no code is issued, and
     * a link the helper committed stands.
     *
     * @param  bool  $provisions
     * @return void
     */
    #[DataProvider('provideListeners')]
    public function testAnApplicationRefusedDuringTheListenerRefusesTheFinish(bool $provisions): void
    {
        config()->set('sso.applications.web.unlinked_handoffs', true);

        $this->start();

        $this->onOffer(function (ResultUnlinked $event) use ($provisions): void {

            if ($provisions) {
                self::assertTrue($this->provision($event)->isCreated());
            }

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
        });

        $completion = $this->complete();

        self::assertSame(FailureReason::APPLICATION_NOT_ALLOWED, $completion->reason);
        self::assertNull($completion->handoff);
        self::assertSame(0, HandoffCode::query()->count());
        self::assertSame($provisions ? 1 : 0, Link::query()->count());
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::APPLICATION_NOT_ALLOWED);
    }

    /**
     * A request the helper finds unconsumed or finished is
     * `request_unavailable` even under the current trust version.
     *
     * @return void
     */
    public function testARequestNoLongerConsumedAndUnfinishedRefusesTheHelper(): void
    {
        foreach (['unconsumed', 'finished'] as $how) {

            $this->answers = [];

            AuthorizationRequest::query()->delete();
            Event::forget(ResultUnlinked::class);

            $this->start();

            $this->onOffer(function (ResultUnlinked $event) use ($how): void {
                $this->withdraw($how);
                $this->provision($event);
            });

            self::assertSame(FailureReason::UNLINKED, $this->complete()->reason, $how);
            self::assertSame([ProvisioningStatus::REQUEST_UNAVAILABLE], $this->statuses(), $how);
            self::assertSame(0, Link::query()->count(), $how);
        }
    }

    /**
     * What was fetched for the connection expires exactly at its stale limit:
     * one second before it, the helper still links.
     *
     * @return void
     */
    public function testMetadataOneSecondBeforeItsStaleLimitStillStands(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {
            $this->connection->forceFill(['jwks_fetched_at' => $this->clock->now()->subSeconds(self::STALE_LIMIT - 1)])->save();
            $this->provision($event);
        });

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame([ProvisioningStatus::CREATED], $this->statuses());
    }

    /**
     * A trust change refused in the helper is the trust version, not the
     * connection, that refuses: a receipt naming exactly that transition lets
     * the helper and the final continuation go on, and a further change does
     * not.
     *
     * @return void
     */
    public function testTheResponsesOwnReceiptPermitsExactlyItsTransition(): void
    {
        $this->arrangeReceipt();
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {
            self::assertInstanceOf(TransitionReceipt::class, $event->grant->transitionReceipt());

            $this->provision($event);
        });

        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());
        self::assertSame([ProvisioningStatus::CREATED], $this->statuses());
        self::assertSame(1, $this->connection->refresh()->trust_version);
    }

    /**
     * A further trust change during the listener is beyond the receipt.
     *
     * @return void
     */
    public function testAFurtherTrustChangeIsBeyondTheReceipt(): void
    {
        $this->arrangeReceipt();
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {
            $this->withdraw('trust');
            $this->provision($event);
        });

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->complete()->reason);
        self::assertSame([ProvisioningStatus::REQUEST_UNAVAILABLE], $this->statuses());
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Rows of `[seconds, status, the final continuation's reason]` of a
     * listener the clock moves on during: the deadline is exact, passed at its
     * moment.
     *
     * @return iterable<string, array{0: int, 1: \SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideDeadlines(): iterable
    {
        yield 'one second before' => [self::MAX_AGE - 1, ProvisioningStatus::CREATED, null];
        yield 'at the deadline' => [self::MAX_AGE, ProvisioningStatus::EXPIRED, FailureReason::REQUEST_EXPIRED];
        yield 'one second after' => [self::MAX_AGE + 1, ProvisioningStatus::EXPIRED, FailureReason::REQUEST_EXPIRED];
    }

    /**
     * The helper judges the verified response's deadline under its locks, and
     * the final continuation in its turn.
     *
     * @param  int  $seconds
     * @param  \SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus  $status
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $final
     * @return void
     */
    #[DataProvider('provideDeadlines')]
    public function testTheDeadlineAtTheHelper(int $seconds, ProvisioningStatus $status, ?FailureReason $final): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event) use ($seconds): void {
            $this->clock->advance($seconds);
            $this->provision($event);
        });

        $completion = $this->complete();

        self::assertSame([$status], $this->statuses());
        self::assertSame($final, $completion->reason);
        self::assertSame($final === null ? 1 : 0, Link::query()->count());
    }

    /**
     * A listener that made nothing is judged by the same deadline at the final
     * continuation, on an application that allows unlinked handoffs.
     *
     * @param  int  $seconds
     * @param  \SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus  $status
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $final
     * @return void
     */
    #[DataProvider('provideDeadlines')]
    public function testTheDeadlineAtTheFinalContinuation(int $seconds, ProvisioningStatus $status, ?FailureReason $final): void
    {
        unset($status);

        config()->set('sso.applications.web.unlinked_handoffs', true);

        $this->start();

        $this->onOffer(function () use ($seconds): void {
            $this->clock->advance($seconds);
        });

        $completion = $this->complete();

        self::assertSame($final, $completion->reason);
        self::assertSame($final === null, $completion->isCompleted());
    }

    /**
     * A link made in time and a final continuation out of time leave the link
     * made, and the completion refused: a provisioned identity can survive.
     *
     * @return void
     */
    public function testALinkMadeBeforeTheDeadlineSurvivesARefusalAfterIt(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {
            $this->clock->advance(self::MAX_AGE - 1);
            $this->provision($event);
            $this->clock->advance(1);
        });

        $completion = $this->complete();

        self::assertSame([ProvisioningStatus::CREATED], $this->statuses());
        self::assertSame(FailureReason::REQUEST_EXPIRED, $completion->reason);
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::REQUEST_EXPIRED);
    }

    /**
     * The request's own expiry bounds the deadline when it comes first,
     * exactly.
     *
     * @return void
     */
    public function testTheRequestsExpiryBoundsTheDeadline(): void
    {
        foreach ([[29, ProvisioningStatus::CREATED], [30, ProvisioningStatus::EXPIRED]] as [$seconds, $status]) {

            $this->answers = [];

            Link::query()->delete();
            AuthorizationRequest::query()->delete();
            Event::forget(ResultUnlinked::class);

            $this->start();

            AuthorizationRequest::query()->sole()->forceFill(['expires_at' => $this->clock->now()->addSeconds(30)])->save();

            $this->onOffer(function (ResultUnlinked $event) use ($seconds): void {
                $this->clock->advance($seconds);
                $this->provision($event);
            });

            $this->complete();

            self::assertSame([$status], $this->statuses(), (string) $seconds);
        }
    }

    /**
     * What a listener's commit, or a change during it, leaves for a final
     * continuation that refuses: `[how, reason]`.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideRefusalsAfterTheLink(): iterable
    {
        yield 'the request voided' => ['voided', FailureReason::CONNECTION_UNAVAILABLE];
        yield 'the trust changed' => ['trust', FailureReason::CONNECTION_UNAVAILABLE];
        yield 'the connection disabled' => ['disabled', FailureReason::CONNECTION_UNAVAILABLE];
        yield 'the metadata expired' => ['metadata_expired', FailureReason::METADATA_EXPIRED];
    }

    /**
     * A listener commits its link, then the final continuation refuses: the
     * link survives, one failure is reported, and no code is kept.
     *
     * @param  string  $how
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $final
     * @return void
     */
    #[DataProvider('provideRefusalsAfterTheLink')]
    public function testACommittedLinkSurvivesARefusingFinalContinuation(string $how, FailureReason $final): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event) use ($how): void {
            $this->provision($event);
            $this->withdraw($how);
        });

        $completion = $this->complete();

        self::assertSame([ProvisioningStatus::CREATED], $this->statuses());
        self::assertSame($final, $completion->reason);
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        self::assertSame(0, HandoffCode::query()->count());
        $this->assertExactlyOneFailure(Flow::CALLBACK, $final);
    }

    /**
     * A subject linked by a racer before the helper is refused, under the lock,
     * and the final continuation resolves to the racer's identity with the
     * racer's link, whichever identity the listener tried.
     *
     * @return void
     */
    public function testASubjectLinkedByARacerResolvesToTheRacersIdentity(): void
    {
        $start = $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {
            app(LinkStore::class)->create($this->connection, LinkSubject::of($event->result), $this->other, LinkOrigin::LINK_PURPOSE);

            $this->provision($event);
        });

        $completion = $this->complete();

        self::assertSame([ProvisioningStatus::SUBJECT_ALREADY_LINKED], $this->statuses());
        self::assertSame(FailureReason::SUBJECT_ALREADY_LINKED, $this->answers[0]->reason());
        self::assertTrue($completion->isCompleted());

        $link     = Link::query()->sole();
        $redeemed = $this->admit($completion, $start);

        self::assertSame($this->other->id, $link->identity_id);
        self::assertSame($this->other->id, $redeemed->linkedIdentity?->id);
        self::assertSame($link->id, $redeemed->linkId);
    }

    /**
     * The subject held is judged before the identity's limit: a subject already
     * linked to the very identity at its limit is not a reached limit.
     *
     * @return void
     */
    public function testASubjectHeldIsJudgedBeforeTheLimit(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {
            app(LinkStore::class)->create($this->connection, LinkSubject::of($event->result), $this->person, LinkOrigin::LINK_PURPOSE);

            $this->provision($event);
        });

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame([ProvisioningStatus::SUBJECT_ALREADY_LINKED], $this->statuses());
    }

    /**
     * A subject suspended or reserved during the listener refuses the helper,
     * and the final continuation ends on it, never with an unlinked handoff.
     *
     * @return void
     */
    public function testASubjectSuspendedOrReservedDuringTheListenerRefuses(): void
    {
        config()->set('sso.applications.web.unlinked_handoffs', true);

        $cases = [
            [LinkState::SUSPENDED, null, FailureReason::LINK_SUSPENDED],
            [LinkState::RESERVED, $this->clock->now()->addSecond(), FailureReason::LINK_RESERVED],
        ];

        foreach ($cases as [$state, $expires, $final]) {

            $this->answers = [];

            Link::query()->delete();
            AuthorizationRequest::query()->delete();
            Event::forget(ResultUnlinked::class);

            $this->start();

            $this->onOffer(function (ResultUnlinked $event) use ($state, $expires): void {
                $this->holdTheSubject($state, $expires);
                $this->provision($event);
            });

            $completion = $this->complete();

            self::assertSame([ProvisioningStatus::SUBJECT_ALREADY_LINKED], $this->statuses(), $state->value);
            self::assertSame($final, $completion->reason);
            self::assertSame($state, Link::query()->sole()->state);
        }
    }

    /**
     * An expired reservation, at its expiry or past it, is logically absent:
     * the helper replaces it.
     *
     * @return void
     */
    public function testAnExpiredReservationIsReplaced(): void
    {
        foreach ([0, -1] as $seconds) {

            $this->answers = [];

            Link::query()->delete();
            AuthorizationRequest::query()->delete();
            Event::forget(ResultUnlinked::class);

            $this->start();

            $this->onOffer(function (ResultUnlinked $event) use ($seconds): void {
                $this->holdTheSubject(LinkState::RESERVED, $this->clock->now()->addSeconds($seconds));
                $this->provision($event);
            });

            self::assertTrue($this->complete()->isCompleted(), (string) $seconds);
            self::assertSame([ProvisioningStatus::CREATED], $this->statuses(), (string) $seconds);

            $link = Link::query()->sole();

            self::assertSame(LinkState::ACTIVE, $link->state);
            self::assertSame(LinkOrigin::PROVISIONING, $link->provenance);
            self::assertNull($link->reservation_id);
            self::assertSame($this->person->id, $link->identity_id);
        }
    }

    /**
     * The identity at its limit is `link_limit_reached`, with nothing written:
     * the limit counts through the store, and the identity's other link stays.
     *
     * @return void
     */
    public function testTheLimitReachedIsRefused(): void
    {
        $this->holdTheLimitOf($this->person);
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {
            $this->provision($event);
        });

        $completion = $this->complete();

        self::assertSame([ProvisioningStatus::LINK_LIMIT_REACHED], $this->statuses());
        self::assertSame(1, $this->connection->refresh()->links_version);
        self::assertSame(FailureReason::UNLINKED, $completion->reason);
    }

    /**
     * Each state of the link that is not genuinely absent, and what it ends
     * with: a suspended link and a live reservation are never offered, even on
     * an application allowing unlinked handoffs.
     *
     * @return void
     */
    public function testASuspendedLinkOrALiveReservationIsNeverOffered(): void
    {
        config()->set('sso.applications.web.unlinked_handoffs', true);

        $this->holdTheSubject(LinkState::SUSPENDED, null);
        $this->start();

        self::assertSame(FailureReason::LINK_SUSPENDED, $this->complete()->reason);
        self::assertSame(0, $this->offered);

        Link::query()->delete();

        $this->holdTheSubject(LinkState::RESERVED, $this->clock->now()->addSecond());
        $this->start();

        self::assertSame(FailureReason::LINK_RESERVED, $this->complete()->reason);
        self::assertSame(0, $this->offered);
    }

    /**
     * A linked result is never offered, and finishes with its link.
     *
     * @return void
     */
    public function testALinkedResultIsNeverOffered(): void
    {
        $this->linkTheSubject();
        $start = $this->start();

        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());
        self::assertSame(0, $this->offered);
        self::assertSame($this->person->id, $this->admit($completion, $start)->linkedIdentity?->id);
    }

    /**
     * A result that reserved a link through a verified domain is never offered.
     *
     * @return void
     */
    public function testAReservedResultIsNeverOffered(): void
    {
        $this->matcher->match = LinkEmailMatch::exactlyOne($this->person);

        $this->start();

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame(0, $this->offered);
        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
    }

    /**
     * A `link` result, its subject unlinked, is never offered.
     *
     * @return void
     */
    public function testALinkResultIsNeverOffered(): void
    {
        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $this->start(Purpose::LINK, $this->person);

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame(0, $this->offered);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * A `reauthenticate` result is never offered.
     *
     * @return void
     */
    public function testAReauthenticateResultIsNeverOffered(): void
    {
        $link = $this->linkTheSubject();

        $this->app?->instance(ReauthenticationSessions::class, new RecordingSessions($link->id));

        $this->start(Purpose::REAUTHENTICATE, $this->person, 'session-1');

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame(0, $this->offered);
    }

    /**
     * A result still unlinked, with unlinked handoffs off, ends `unlinked` with
     * no code, the request finished, and one failure.
     *
     * @return void
     */
    public function testStillUnlinkedWithUnlinkedHandoffsOff(): void
    {
        $this->start();

        $completion = $this->complete();

        self::assertTrue($completion->isFailed());
        self::assertSame(FailureReason::UNLINKED, $completion->reason);
        self::assertNull($completion->handoff);
        self::assertSame(1, $this->offered);
        self::assertSame(0, HandoffCode::query()->count());
        self::assertNotNull(AuthorizationRequest::query()->sole()->completed_at);
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::UNLINKED);
    }

    /**
     * A result still unlinked, with unlinked handoffs on, is issued a code that
     * carries no identity, once offered.
     *
     * @return void
     */
    public function testStillUnlinkedWithUnlinkedHandoffsOn(): void
    {
        config()->set('sso.applications.web.unlinked_handoffs', true);

        $start      = $this->start();
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());
        self::assertSame(1, $this->offered);
        self::assertNotNull(AuthorizationRequest::query()->sole()->completed_at);

        $redeemed = $this->admit($completion, $start);

        self::assertTrue($redeemed->isRedeemed());
        self::assertNull($redeemed->linkedIdentity);
        self::assertNull($redeemed->linkId);
    }

    /**
     * The final continuation records no replay again: the single-use store
     * holds the request's record and the response's one, and no more.
     *
     * @return void
     */
    public function testTheFinalContinuationRecordsNoReplayAgain(): void
    {
        $this->verifying->replay = ReplayRecord::samlAssertion($this->connection->id, VerifyingDriver::ISSUER, 'assertion-1', $this->clock->now()->addMinutes(5));

        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {

            self::assertSame(1, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());
            self::assertSame(2, SingleUseKey::query()->count());

            $this->provision($event);
        });

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame(1, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());
        self::assertSame(2, SingleUseKey::query()->count());
    }

    /**
     * The lock order of the whole completion from validation on, under no
     * enforcement: the preparation with the domain claim, the helper's request
     * by the id it claimed and its links, and a final continuation that selects
     * no domain.
     *
     * @return void
     */
    public function testTheLockOrderAcrossThePreparationTheHelperAndTheFinalContinuation(): void
    {
        $this->start();

        $this->verifying->onComplete = function (): void {
            $this->recordLockOrder();
        };

        $this->onOffer(function (ResultUnlinked $event): void {
            $this->provision($event);
        });

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame(
            [
                'connections', 'sso_domains', 'request', 'link',
                'connections', 'request', 'link', 'connections', 'link', 'link',
                'connections', 'request', 'link',
            ],
            $this->lockedTables(),
        );
    }

    /**
     * Under enforcement, the final continuation takes the guard again, before
     * the connection, and no domain.
     *
     * @return void
     */
    public function testTheFinalContinuationTakesTheEnforcementGuardAgain(): void
    {
        config()->set('sso.features.enforcement', true);

        $this->start();

        $this->verifying->onComplete = function (): void {
            $this->recordLockOrder();
        };

        self::assertSame(FailureReason::UNLINKED, $this->complete()->reason);
        self::assertSame(
            ['enforcement', 'enforcement', 'connections', 'sso_domains', 'request', 'link', 'enforcement', 'enforcement', 'connections', 'request', 'link'],
            $this->lockedTables(),
        );
    }

    /**
     * Rows of `[what is missing of the state, the message]`: an offer that
     * could never be a dispatch of a verified, consumed result.
     *
     * @return iterable<string, array{0: int, 1: string}>
     */
    public static function provideOutOfTurnOffers(): iterable
    {
        yield 'no result' => [0, 'A result is offered for provisioning once it is verified.'];
        yield 'no request' => [1, 'A result is offered for provisioning once its request is consumed.'];
        yield 'no deadline' => [2, 'A result is offered for provisioning with its deadline.'];
    }

    /**
     * What is out of turn is a misconfiguration, dispatching nothing.
     *
     * @param  int  $parts
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideOutOfTurnOffers')]
    public function testAnOfferOutOfTurnIsALogicException(int $parts, string $message): void
    {
        $start = $this->start();
        $state = CompletionState::arrived($this->connection->id, new CompletionRequest('GET', '', []));

        if ($parts > 0) {
            $state = $state->withResult(new VerifiedResult(
                issuer: VerifyingDriver::ISSUER,
                subject: VerifyingDriver::SUBJECT,
                nameIdFormat: null,
                connectionId: $this->connection->id,
                tenantId: 'tenant-1',
                protocol: VerifyingDriver::NAME,
                application: 'web',
                purpose: Purpose::SIGN_IN,
                requestReference: RequestReference::fromString((string) $start->reference?->value),
                attributes: [],
                emailDomainVerified: false,
                authenticationContext: new AuthenticationContext($this->clock->now()),
            ));
        }

        if ($parts > 1) {
            $state = $state->withAuthorizationRequest(AuthorizationRequest::query()->sole(), null, null);
        }

        $this->expectExceptionObject(new \LogicException($message));

        app(ProvisioningOffer::class)->dispatch($state);
    }

    /**
     * Under enforcement, the helper takes the enforcing tenant's rule first.
     *
     * @return void
     */
    public function testTheHelperTakesTheEnforcementGuardFirst(): void
    {
        config()->set('sso.features.enforcement', true);

        $this->start();

        $order = [];

        $this->onOffer(function (ResultUnlinked $event) use (&$order): void {

            $this->recordLockOrder();
            $this->provision($event);

            $order = $this->lockedTables();
        });

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame(['enforcement', 'enforcement', 'connections', 'request', 'link', 'connections', 'link', 'link'], $order);
    }

    /**
     * An enforcing tenant that moved between the helper's lock and its check is
     * `request_unavailable`; the rule locked is no longer the one that applies.
     *
     * @return void
     */
    public function testAnEnforcingTenantThatMovedRefusesTheHelper(): void
    {
        config()->set('sso.features.enforcement', true);

        $inheritance = new class implements EnforcementInheritance {
            /** @var list<string> What it answers next, before its own tenant. */
            public array $answers = [];

            /**
             * The next answer, or the tenant asked about.
             *
             * @param  string  $tenantId
             * @param  string  $application
             * @return string
             */
            #[\Override]
            public function enforcingTenant(string $tenantId, string $application): string
            {
                unset($application);

                return array_shift($this->answers) ?? $tenantId;
            }
        };

        $this->app?->instance(EnforcementInheritance::class, $inheritance);

        $this->start();

        $this->onOffer(function (ResultUnlinked $event) use ($inheritance): void {

            $inheritance->answers = ['tenant-1', 'another-tenant'];

            $this->provision($event);
        });

        self::assertSame(FailureReason::UNLINKED, $this->complete()->reason);
        self::assertSame([ProvisioningStatus::REQUEST_UNAVAILABLE], $this->statuses());
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Rows of `[seconds to the reservation's expiry, or `null` for none, what
     * the helper answers]`.
     *
     * @return iterable<string, array{0: ?int, 1: \SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus}>
     */
    public static function provideReservationsInTheWay(): iterable
    {
        yield 'none stated' => [null, ProvisioningStatus::CREATED];
        yield 'expired' => [0, ProvisioningStatus::CREATED];
        yield 'live' => [1, ProvisioningStatus::SUBJECT_ALREADY_LINKED];
    }

    /**
     * A reservation stands in the helper's way only while it is live.
     *
     * @param  ?int  $seconds
     * @param  \SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus  $status
     * @return void
     */
    #[DataProvider('provideReservationsInTheWay')]
    public function testOnlyALiveReservationHoldsTheSubjectFromTheHelper(?int $seconds, ProvisioningStatus $status): void
    {
        $this->start();

        $answers = [];

        $this->onOffer(function (ResultUnlinked $event) use ($seconds, &$answers): void {

            $this->holdTheSubject(LinkState::RESERVED, $seconds === null ? null : $this->clock->now()->addSeconds($seconds));

            $answers[] = $this->provision($event)->status;
        });

        $this->complete();

        self::assertSame([$status], $answers);
    }

    /**
     * Listen for the result being offered.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Events\ResultUnlinked): void  $listener
     * @return void
     */
    private function onOffer(\Closure $listener): void
    {
        Event::listen(ResultUnlinked::class, $listener);
    }

    /**
     * Ask the helper to link the event's result, and keep what it answered.
     *
     * @param  \SineMacula\Laravel\Sso\Events\ResultUnlinked  $event
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Provisioning\ProvisioningResult
     */
    private function provision(ResultUnlinked $event, ?IdentityReference $identity = null): ProvisioningResult
    {
        $answer = app(ProvisioningHelper::class)->link($event->grant, $event->result, $identity ?? $this->person);

        $this->answers[] = $answer;

        return $answer;
    }

    /**
     * The status of each answer the helper gave.
     *
     * @return list<\SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus>
     */
    private function statuses(): array
    {
        return array_map(static fn (ProvisioningResult $answer): ProvisioningStatus => $answer->status, $this->answers);
    }

    /**
     * Assert the completion throws what the listener threw.
     *
     * @param  string  $message
     * @return void
     */
    private function assertListenerFailure(string $message): void
    {
        try {
            $this->complete();

            self::fail('The completion went on.');
        } catch (\RuntimeException $exception) {
            self::assertSame($message, $exception->getMessage());
        }
    }

    /**
     * Assert the request is consumed and unfinished, and no code exists.
     *
     * @return void
     */
    private function assertConsumedAndUnfinished(): void
    {
        $request = AuthorizationRequest::query()->sole();

        self::assertNotNull($request->consumed_at);
        self::assertNotNull($request->verified_at);
        self::assertNull($request->completed_at);
        self::assertSame(0, HandoffCode::query()->count());
    }

    /**
     * Assert the text shows nothing of the result.
     *
     * @param  string  $text
     * @param  string  $how
     * @return void
     */
    private function assertShowsNothingOfTheResult(string $text, string $how): void
    {
        foreach ([trim(VerifyingDriver::SUBJECT), VerifyingDriver::ISSUER, self::EMAIL, 'attributes', AuthorizationRequest::query()->sole()->id] as $secret) {
            self::assertStringNotContainsString($secret, $text, $how);
        }
    }

    /**
     * What `serialize()` writes of an object of the class with no properties.
     *
     * @param  string  $class
     * @return string
     */
    private static function emptyPayload(string $class): string
    {
        return 'O:' . strlen($class) . ':"' . $class . '":0:{}';
    }

    /**
     * The result, serialised and read back.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private static function roundTrip(VerifiedResult $result): VerifiedResult
    {
        /** @var \SineMacula\Laravel\Sso\Results\VerifiedResult */
        return unserialize(serialize($result));
    }

    /**
     * The exception at the bottom of the chain: Laravel's queue wraps what a
     * refused serialisation throws in its own exception.
     *
     * @param  \Throwable  $exception
     * @return \Throwable
     */
    private static function rootCause(\Throwable $exception): \Throwable
    {
        while ($exception->getPrevious() !== null) {
            $exception = $exception->getPrevious();
        }

        return $exception;
    }

    /**
     * The exception's message when the callback throws a `LogicException`.
     *
     * @param  \Closure(): mixed  $callback
     * @return string
     */
    private static function refusalOf(\Closure $callback): string
    {
        try {
            $callback();
        } catch (\LogicException $exception) {
            return $exception->getMessage();
        }

        return 'nothing refused it';
    }

    /**
     * Whether a link's creation has been reported.
     *
     * @return bool
     */
    private function hasSeenLinkCreated(): bool
    {
        return array_filter($this->recordedEvents(), static fn (object $event): bool => $event instanceof LinkCreated) !== [];
    }

    /**
     * Write an identity through the application's table.
     *
     * @return void
     */
    private function writeIdentity(): void
    {
        DB::connection(StorageConnection::name())->table(self::IDENTITIES)->insert(['id' => $this->person->id]);
    }

    /**
     * How many identities the application's table holds.
     *
     * @return int
     */
    private function identities(): int
    {
        return DB::connection(StorageConnection::name())->table(self::IDENTITIES)->count();
    }

    /**
     * Take away the request's or the connection's authority, as named.
     *
     * @param  string  $how
     * @return void
     *
     * @throws \LogicException
     */
    private function withdraw(string $how): void
    {
        $request = AuthorizationRequest::query()->sole();
        $now     = $this->clock->now();

        match ($how) {
            'voided'           => $request->forceFill(['voided_at' => $now])->save(),
            'finished'         => $request->forceFill(['completed_at' => $now])->save(),
            'unconsumed'       => $request->forceFill(['consumed_at' => null])->save(),
            'request_gone'     => $request->delete(),
            'trust'            => Connection::query()->whereKey($this->connection->id)->increment('trust_version'),
            'disabled'         => $this->connection->forceFill(['enabled' => false])->save(),
            'connection_gone'  => $this->connection->delete(),
            'metadata_expired' => $this->connection->forceFill(['jwks_fetched_at' => $now->subSeconds(self::STALE_LIMIT)])->save(),
            default            => throw new \LogicException(sprintf('No withdrawal is named [%s].', $how)),
        };
    }

    /**
     * Fill the identity's limit of one with a link of another subject.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return void
     */
    private function holdTheLimitOf(IdentityReference $identity): void
    {
        app(LinkStore::class)->create($this->connection, new LinkSubject(VerifyingDriver::ISSUER, 'another-subject'), $identity, LinkOrigin::LINK_PURPOSE);
    }

    /**
     * Make an active link of the subject the driver verifies.
     *
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function linkTheSubject(): Link
    {
        app(LinkStore::class)->create($this->connection, new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT), $this->person, LinkOrigin::PROVISIONING);

        return Link::query()->sole();
    }

    /**
     * A row of the subject the driver verifies, held by another identity in the
     * state given.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $state
     * @param  ?\Carbon\CarbonImmutable  $expires
     * @return void
     */
    private function holdTheSubject(LinkState $state, ?CarbonImmutable $expires): void
    {
        $subject = new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT);
        $row     = new Link;

        $row->forceFill([
            'connection_id'          => $this->connection->id,
            'issuer'                 => $subject->issuer,
            'subject'                => $subject->subject,
            'subject_key'            => $subject->key(),
            'identity_type'          => $this->other->type,
            'identity_id'            => $this->other->id,
            'state'                  => $state,
            'provenance'             => LinkOrigin::VERIFIED_DOMAIN,
            'suspended_at'           => $state === LinkState::SUSPENDED ? $this->clock->now() : null,
            'reservation_id'         => $state === LinkState::RESERVED ? '01jbexamplereservation0001' : null,
            'reservation_expires_at' => $expires,
        ])->save();
    }

    /**
     * The first word of each lock taken, the tables the completion's lock order
     * names and no other.
     *
     * @return list<string>
     */
    private function lockedTables(): array
    {
        $names = array_map(static fn (string $lock): string => explode(' ', $lock)[0], $this->lockOrder());

        return array_values(array_filter($names, static fn (string $name): bool => in_array($name, ['enforcement', 'connections', 'sso_domains', 'request', 'link'], true)));
    }

    /**
     * Arrange a response whose own validation rotated the connection's keys:
     * the connection stores the key and raises its trust version during
     * validation, and the validation step answers the receipt naming that
     * transition.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function arrangeReceipt(): void
    {
        $allowed = AlgorithmAllowList::of(['RS256']);
        $key     = FakeSigningKey::rsa('rsa-1');
        $stored  = ProviderKeySet::read((string) json_encode(['keys' => [$key->jwk()]]), $allowed, 65536, 50)?->toStored();
        $admit   = ProviderKey::admit($key->jwk(), $allowed) ?? throw new \LogicException('The key is admitted.');

        $this->connection->forceFill([
            'jwks_version' => 7,
            'jwks'         => $stored,
            'settings'     => ['issuer' => VerifyingDriver::ISSUER, 'id_token_algorithms' => ['RS256']],
        ])->save();

        $connection = $this->connection;
        $thumbprint = $admit->thumbprint();

        $validation = static fn (): ValidateResponse => new ValidateResponse(app(ProtocolManager::class), app(ResultBuilder::class), app(VerifiedDeadlines::class));

        app()->bind(ValidateResponse::class, static fn (): CompletionStage => new readonly class ($validation(), $connection, $thumbprint) implements CompletionStage {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Completion\Stages\ValidateResponse  $inner
             * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
             * @param  string  $thumbprint
             */
            public function __construct(

                /** The validation step itself. */
                private ValidateResponse $inner,

                /** The connection whose keys rotate. */
                private Connection $connection,

                /** The thumbprint of the key the response verified with. */
                private string $thumbprint,
            ) {}

            /**
             * Validate, rotate, and answer the receipt of the rotation.
             *
             * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
             * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
             */
            #[\Override]
            public function run(CompletionState $state): StageOutcome
            {
                $outcome = $this->inner->run($state);
                $request = (string) $state->authorizationRequest?->id;

                Connection::query()->whereKey($this->connection->id)->increment('trust_version');

                return StageOutcome::proceed($outcome->state->withTransitionReceipt(new TransitionReceipt($this->connection->id, $request, 0, 1, 7, $this->thumbprint, 'RS256')));
            }
        });
    }
}
