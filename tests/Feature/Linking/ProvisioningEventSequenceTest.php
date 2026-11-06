<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionEvents;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\ProvisioningOffer;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningResult;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * The events of an unlinked `sign_in`, in order (SSO-8.6, SSO-10.5): the one
 * event that is synchronous, with no package transaction open, then what the
 * listener made, then how the completion ended; `ResultVerified` once on every
 * path, and the whole context each carries.
 *
 * Its listeners listen on `Contracts\SsoEvent` and filter, so they run after
 * the recording listener, which then sees the offer before what the listener
 * makes of it, and sees it though a listener throws. A listener on the event's
 * own class runs before a listener on its interface, and would record the other
 * way round.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionEvents::class)]
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(ProvisioningOffer::class)]
#[CoversClass(ProvisioningHelper::class)]
#[CoversClass(ResultUnlinked::class)]
final class ProvisioningEventSequenceTest extends LinkingTestCase
{
    /** @var string The time every event is built at. */
    private const string OCCURRED_AT = '2026-11-01T09:30:00.000000Z';

    /** @var string The IP address the completion comes from: the client the flow is started and completed for. */
    private const string IP = Clients::IP;

    /** @var string The user agent the completion comes from. */
    private const string USER_AGENT = Clients::USER_AGENT;

    /**
     * Make the result unmatched by any verified domain.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->matcher->match = LinkEmailMatch::none();
    }

    /**
     * Provisioned: started, verified, offered, the link created with its
     * origin, and the handoff, each once and in that order.
     *
     * @return void
     */
    public function testAProvisionedResultReportsItsLinkBetweenTheOfferAndTheHandoff(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {
            $this->provision($event);
        });

        self::assertTrue($this->complete()->isCompleted());

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, ResultUnlinked::class, LinkCreated::class, HandoffIssued::class]);

        $created = $this->recordedEvents()[3];

        self::assertInstanceOf(LinkCreated::class, $created);
        self::assertSame(LinkOrigin::PROVISIONING, $created->origin);
    }

    /**
     * Not provisioned: started, verified, offered, and one `unlinked` failure.
     *
     * @return void
     */
    public function testAResultNotProvisionedEndsUnlinked(): void
    {
        $this->start();

        self::assertSame(FailureReason::UNLINKED, $this->complete()->reason);

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, ResultUnlinked::class, FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::UNLINKED);
    }

    /**
     * An allowed unlinked handoff: started, verified, offered, and the handoff.
     *
     * @return void
     */
    public function testAnAllowedUnlinkedHandoffIsIssuedAfterTheOffer(): void
    {
        config()->set('sso.applications.web.unlinked_handoffs', true);

        $this->start();

        self::assertTrue($this->complete()->isCompleted());

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, ResultUnlinked::class, HandoffIssued::class]);
    }

    /**
     * A listener's exception: started, verified, offered, and nothing after.
     *
     * @return void
     */
    public function testAListenersExceptionReportsNothingAfterTheOffer(): void
    {
        $this->start();

        $this->onOffer(static function (): void {
            throw new \RuntimeException('The listener failed.');
        });

        try {
            $this->complete();

            self::fail('The completion went on.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The listener failed.', $exception->getMessage());
        }

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, ResultUnlinked::class]);
    }

    /**
     * A link committed, then a refusal: the link's event stands, and the
     * failure follows it, with the result reported verified once.
     *
     * @return void
     */
    public function testALinkThenARefusalReportsBoth(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {
            $this->provision($event);
            $this->connection->forceFill(['enabled' => false])->save();
        });

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->complete()->reason);

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, ResultUnlinked::class, LinkCreated::class, FlowFailed::class]);
    }

    /**
     * A refusal by the helper reports nothing of its own.
     *
     * @return void
     */
    public function testARefusedHelperReportsNoLink(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {
            $this->connection->forceFill(['enabled' => false])->save();

            self::assertTrue($this->provision($event)->isRefused());
        });

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->complete()->reason);

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, ResultUnlinked::class, FlowFailed::class]);
    }

    /**
     * The link's event waits for the outer commit of the listener's
     * transaction.
     *
     * @return void
     */
    public function testTheLinksEventWaitsForTheOuterCommit(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {

            $database = DB::connection(StorageConnection::name());

            $database->beginTransaction();

            self::assertTrue($this->provision($event)->isCreated());

            $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, ResultUnlinked::class]);

            $database->commit();

            $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, ResultUnlinked::class, LinkCreated::class]);
        });

        self::assertTrue($this->complete()->isCompleted());
    }

    /**
     * The event is dispatched with no package transaction open, the result
     * reported verified and committed, the request unfinished, and no handoff
     * issued; the grant closes when the dispatch ends.
     *
     * @return void
     */
    public function testTheEventIsSynchronousWithNoTransactionOpen(): void
    {
        $this->start();

        $seen = [];
        $kept = null;

        $this->onOffer(function (ResultUnlinked $event) use (&$seen, &$kept): void {

            $request = AuthorizationRequest::query()->sole();
            $kept    = $event;

            $seen = [
                DB::connection(StorageConnection::name())->transactionLevel(),
                $event->grant->isUsable(),
                $request->verified_at !== null,
                $request->completed_at === null,
                array_map(static fn (SsoEvent $recorded): string => $recorded::class, $this->recordedEvents()),
            ];
        });

        $this->complete();

        self::assertSame([0, true, true, true, [AuthorizationRequestStarted::class, ResultVerified::class, ResultUnlinked::class]], $seen);
        self::assertInstanceOf(ResultUnlinked::class, $kept);
        self::assertFalse($kept->grant->isUsable());
    }

    /**
     * Each event's whole context: no identity until the link was made, the same
     * reference throughout, and nothing of the result.
     *
     * @return void
     */
    public function testTheWholeContextOfEachEvent(): void
    {
        $this->start();

        $this->onOffer(function (ResultUnlinked $event): void {
            $this->provision($event);
        });

        $this->complete();

        $reference = AuthorizationRequest::query()->sole()->reference;
        $unknown   = $this->context($reference);
        $known     = array_merge($unknown, ['identity_morph_class' => $this->person->type, 'identity_id' => $this->person->id]);
        $contexts  = array_map(static fn (SsoEvent $event): array => $event->context()->toArray(), $this->recordedEvents());

        self::assertSame($unknown, $contexts[1]);
        self::assertSame($unknown, $contexts[2]);
        self::assertSame($known, $contexts[3]);
        self::assertSame($known, $contexts[4]);
    }

    /**
     * Listen for the offer on the interface, after the recording listener.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Events\ResultUnlinked): void  $listener
     * @return void
     */
    private function onOffer(\Closure $listener): void
    {
        Event::listen(SsoEvent::class, static function (SsoEvent $event) use ($listener): void {
            if (!$event instanceof ResultUnlinked) {
                return;
            }

            $listener($event);
        });
    }

    /**
     * Link the event's result to the person.
     *
     * @param  \SineMacula\Laravel\Sso\Events\ResultUnlinked  $event
     * @return \SineMacula\Laravel\Sso\Provisioning\ProvisioningResult
     */
    private function provision(ResultUnlinked $event): ProvisioningResult
    {
        return app(ProvisioningHelper::class)->link($event->grant, $event->result, $this->person, self::client());
    }

    /**
     * The context of an event of this completion that names no identity.
     *
     * @param  string  $reference
     * @return array<string, ?string>
     */
    private function context(string $reference): array
    {
        return [
            'occurred_at'                 => self::OCCURRED_AT,
            'ip'                          => self::IP,
            'user_agent'                  => self::USER_AGENT,
            'connection_id'               => $this->connection->id,
            'connection_tenant_id'        => 'tenant-1',
            'protocol'                    => VerifyingDriver::NAME,
            'application'                 => 'web',
            'purpose'                     => 'sign_in',
            'request_reference'           => $reference,
            'identity_morph_class'        => null,
            'identity_id'                 => null,
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
     * The client every action of the test is taken for: the browser's IP
     * address and user agent, which its events carry.
     *
     * @return \SineMacula\Laravel\Sso\Http\ClientContext
     */
    private static function client(): ClientContext
    {
        return new ClientContext(self::IP, self::USER_AGENT);
    }
}
