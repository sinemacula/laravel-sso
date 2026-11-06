<?php

declare(strict_types = 1);

namespace Tests\Feature\Flows;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestEvents;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the reporter of a start (SSO-5.1, SSO-10.1, SSO-10.2,
 * SSO-10.4): a request started and a start refused, each dispatched once with
 * what the start had established and the IP address and user agent of the
 * client the start was made for, never those of the request being served.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequestEvents::class)]
final class RequestEventsTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

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
     * A request started is reported once, with the connection, the request's
     * application, purpose, reference, identity and session, and the client.
     *
     * @return void
     */
    public function testReportsAStartWithItsClient(): void
    {
        $connection = $this->makeConnection();
        $request    = $this->makeAuthorizationRequest($connection, [
            'purpose'       => 'reauthenticate',
            'identity_type' => 'App\Models\User',
            'identity_id'   => '7',
            'session_id'    => 'session-1',
        ]);

        app(RequestEvents::class)->started($connection, $request, new ClientContext('203.0.113.7', 'Example/1.0'));

        $this->assertEventSequence([AuthorizationRequestStarted::class]);

        $context = $this->recordedEvents()[0]->context();

        self::assertSame(
            ['203.0.113.7', 'Example/1.0', $connection->id, 'tenant-1', 'oidc', 'web', 'reauthenticate', $request->reference, '7', 'session-1'],
            [
                $context->ip,
                $context->userAgent,
                $context->connectionId,
                $context->connectionTenantId,
                $context->protocol,
                $context->application,
                $context->purpose,
                $context->requestReference,
                $context->identityId,
                $context->sessionId,
            ],
        );
    }

    /**
     * A start refused once everything was established is reported once under
     * the start's flow, with the application, the connection, the reference and
     * the client.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testReportsARefusalWithWhatTheStartHadEstablished(): void
    {
        $connection  = $this->makeConnection();
        $application = Application::fromSettings('web', ['redirect_uri' => 'https://app.example.com/sso']);
        $reference   = RequestReference::generate();
        $identity    = new IdentityReference('App\Models\User', '7');

        app(RequestEvents::class)->failed(
            FailureReason::FRESHNESS_REQUIRED,
            Purpose::LINK,
            $identity,
            null,
            new ClientContext('203.0.113.7', 'Example/1.0'),
            $application,
            $connection,
            $reference,
        );

        $failure = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::FRESHNESS_REQUIRED);
        $context = $failure->context();

        self::assertSame(
            ['203.0.113.7', 'Example/1.0', $connection->id, 'tenant-1', 'oidc', 'web', 'link', $reference->value, '7'],
            [
                $context->ip,
                $context->userAgent,
                $context->connectionId,
                $context->connectionTenantId,
                $context->protocol,
                $context->application,
                $context->purpose,
                $context->requestReference,
                $context->identityId,
            ],
        );
    }

    /**
     * A start refused before anything was established, for no client, names the
     * purpose alone: no connection, application, reference, address or user
     * agent.
     *
     * @return void
     */
    public function testReportsAnEarlyRefusalForNoClient(): void
    {
        app(RequestEvents::class)->failed(FailureReason::RATE_LIMITED, Purpose::SIGN_IN, null, null, new ClientContext(null, null));

        $context = $this->assertExactlyOneFailure(Flow::AUTHORIZATION_REQUEST, FailureReason::RATE_LIMITED)->context();

        self::assertSame(
            [null, null, null, null, 'sign_in', null],
            [$context->ip, $context->userAgent, $context->connectionId, $context->application, $context->purpose, $context->requestReference],
        );
    }
}
