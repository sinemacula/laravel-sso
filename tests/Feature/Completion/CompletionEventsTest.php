<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionEvents;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Events\UnsolicitedResponseReinitiated;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Results\ExampleResults;
use Tests\TestCase;

/**
 * Feature tests for the reporter of a completion (SSO-10.1, SSO-10.2,
 * SSO-10.4): how a completion ended, a result verified at the provisioning
 * boundary and an unsolicited response re-initiated, each dispatched once,
 * every context carrying the IP address and user agent of the client the
 * completion's state holds, never those of the request being served.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionEvents::class)]
final class CompletionEventsTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /** @var string The IP address of the client the completion arrived from. */
    private const string IP = '203.0.113.7';

    /** @var string The user agent of the client the completion arrived from. */
    private const string USER_AGENT = 'Example/1.0';

    /**
     * Bind a fixed clock and a request being served from another client, create
     * the tables and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance('request', Request::create('/', 'POST', server: ['REMOTE_ADDR' => '198.51.100.9', 'HTTP_USER_AGENT' => 'Served/1.0']));

        $this->usePackageTables();
        $this->startRecordingEvents();
    }

    /**
     * A refusal is reported once under its flow and reason, with the connection
     * the state holds and its client.
     *
     * @return void
     */
    public function testReportsARefusalWithTheStatesClient(): void
    {
        $connection = $this->makeConnection();

        app(CompletionEvents::class)->report(Flow::CALLBACK, StageOutcome::refuse(self::state($connection), FailureReason::REQUEST_UNKNOWN));

        $failure = $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::REQUEST_UNKNOWN);

        self::assertContextOf($failure, $connection);
    }

    /**
     * A completion that goes on with no verified result reports its handoff
     * alone; with one, the result verified first, unless it was reported
     * already; each with the state's client.
     *
     * @return void
     */
    public function testReportsACompletionWithTheStatesClient(): void
    {
        $connection = $this->makeConnection();
        $events     = app(CompletionEvents::class);
        $verified   = self::state($connection)->withResult(ExampleResults::bare(connectionId: $connection->id));

        $events->report(Flow::CALLBACK, StageOutcome::proceed(self::state($connection)));
        $this->assertEventSequence([HandoffIssued::class]);

        $this->startRecordingEvents();
        $events->report(Flow::CALLBACK, StageOutcome::proceed($verified));
        $this->assertEventSequence([ResultVerified::class, HandoffIssued::class]);

        $this->startRecordingEvents();
        $events->report(Flow::ASSERTION, StageOutcome::proceed($verified), true);
        $this->assertEventSequence([HandoffIssued::class]);

        self::assertContextOf($this->recordedEvents()[0], $connection);
    }

    /**
     * A result verified at the provisioning boundary is reported once, and a
     * re-initiation once, each with the client of the completion.
     *
     * @return void
     */
    public function testReportsAVerificationAndAReinitiationWithTheClient(): void
    {
        $connection = $this->makeConnection(['protocol' => 'saml2']);
        $events     = app(CompletionEvents::class);

        $events->verified(self::state($connection));
        $events->reinitiated($connection, new ClientContext(self::IP, self::USER_AGENT));

        $this->assertEventSequence([ResultVerified::class, UnsolicitedResponseReinitiated::class]);

        foreach ($this->recordedEvents() as $event) {
            self::assertContextOf($event, $connection);
        }
    }

    /**
     * The context the reporter builds for a state carries the state's client,
     * and none for a state with no client.
     *
     * @return void
     */
    public function testTheContextCarriesTheStatesClient(): void
    {
        $connection = $this->makeConnection();
        $events     = app(CompletionEvents::class);

        $context = $events->context(self::state($connection));
        $none    = $events->context(CompletionState::arrived($connection->id, new CompletionRequest('GET', '', []), new ClientContext(null, null)));

        self::assertSame([self::IP, self::USER_AGENT, $connection->id], [$context->ip, $context->userAgent, $context->connectionId]);
        self::assertSame([null, null, null], [$none->ip, $none->userAgent, $none->connectionId]);
    }

    /**
     * The state of a completion through the connection, arrived from the
     * client.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     */
    private static function state(Connection $connection): CompletionState
    {
        return CompletionState::arrived($connection->id, new CompletionRequest('GET', '', []), new ClientContext(self::IP, self::USER_AGENT))->withConnection($connection);
    }

    /**
     * Assert the event's context carries the client and names the connection,
     * its tenant and protocol.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     */
    private static function assertContextOf(SsoEvent $event, Connection $connection): void
    {
        $context = $event->context();

        self::assertSame(
            [self::IP, self::USER_AGENT, $connection->id, 'tenant-1', $connection->protocol],
            [$context->ip, $context->userAgent, $context->connectionId, $context->connectionTenantId, $context->protocol],
        );
    }
}
