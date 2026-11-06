<?php

declare(strict_types = 1);

namespace Tests\Feature\Handoffs;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\ReauthenticationCompleted;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffEvents;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the reporter of a redemption (SSO-9.2, SSO-10.1, SSO-10.2,
 * SSO-10.4): a code redeemed, a `reauthenticate` completed with it, and a
 * redemption refused before or after its code was found, each dispatched once
 * with what the redemption had established and the IP address and user agent of
 * the client it was made for, never those of the request being served.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffEvents::class)]
final class HandoffEventsTest extends TestCase
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
     * A `sign_in` code redeemed is reported once, alone, with the identity it
     * established, the code's connection, application and reference, and the
     * client.
     *
     * @return void
     */
    public function testReportsASignInRedeemedWithItsClient(): void
    {
        $connection = $this->makeConnection();
        $code       = $this->makeHandoffCode($connection);

        app(HandoffEvents::class)->redeemed($code, $connection, new ClientContext('203.0.113.7', 'Example/1.0'), new IdentityReference('App\Models\User', '42'));

        $this->assertEventSequence([HandoffRedeemed::class]);

        $context = $this->recordedEvents()[0]->context();

        self::assertSame(
            ['203.0.113.7', 'Example/1.0', $connection->id, 'tenant-1', 'oidc', 'web', 'sign_in', str_repeat('r', 32), '42'],
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
     * A `reauthenticate` code redeemed is reported as redeemed, then as the
     * re-authentication completed, both with the flow's identity, its session
     * and the client.
     *
     * @return void
     */
    public function testReportsAReauthenticationCompletedWithItsClient(): void
    {
        $connection = $this->makeConnection();
        $code       = $this->makeHandoffCode($connection, [
            'purpose'       => Purpose::REAUTHENTICATE,
            'identity_type' => 'App\Models\User',
            'identity_id'   => '7',
            'session_id'    => 'session-1',
        ]);

        app(HandoffEvents::class)->redeemed($code, $connection, new ClientContext('203.0.113.7', 'Example/1.0'));

        $this->assertEventSequence([HandoffRedeemed::class, ReauthenticationCompleted::class]);

        foreach ($this->recordedEvents() as $event) {
            $context = $event->context();

            self::assertSame(
                ['203.0.113.7', 'Example/1.0', 'reauthenticate', '7', 'session-1'],
                [$context->ip, $context->userAgent, $context->purpose, $context->identityId, $context->sessionId],
            );
        }
    }

    /**
     * A redemption refused before any code was found names the purpose asked
     * for and the client alone.
     *
     * @return void
     */
    public function testReportsARefusalBeforeTheCodeWithItsClient(): void
    {
        app(HandoffEvents::class)->refused(FailureReason::HANDOFF_UNKNOWN, Purpose::LINK, new ClientContext('203.0.113.7', 'Example/1.0'));

        $context = $this->assertExactlyOneFailure(Flow::REDEMPTION, FailureReason::HANDOFF_UNKNOWN)->context();

        self::assertSame(
            ['203.0.113.7', 'Example/1.0', 'link', null, null],
            [$context->ip, $context->userAgent, $context->purpose, $context->connectionId, $context->requestReference],
        );
    }

    /**
     * A redemption of a stored code refused is reported once with the code's
     * connection, and its tenant and protocol once the connection was read; for
     * no client, with no address or user agent.
     *
     * @return void
     */
    public function testReportsARefusalOfTheCode(): void
    {
        $connection = $this->makeConnection();
        $code       = $this->makeHandoffCode($connection);
        $events     = app(HandoffEvents::class);

        $events->failed(FailureReason::VERIFIER_MISMATCH, $code, new ClientContext('203.0.113.7', 'Example/1.0'), $connection);

        $context = $this->assertExactlyOneFailure(Flow::REDEMPTION, FailureReason::VERIFIER_MISMATCH)->context();

        self::assertSame(
            ['203.0.113.7', 'Example/1.0', $connection->id, 'tenant-1', 'oidc'],
            [$context->ip, $context->userAgent, $context->connectionId, $context->connectionTenantId, $context->protocol],
        );

        $this->startRecordingEvents();

        $events->failed(FailureReason::CONNECTION_UNAVAILABLE, $code, new ClientContext(null, null));

        $context = $this->assertExactlyOneFailure(Flow::REDEMPTION, FailureReason::CONNECTION_UNAVAILABLE)->context();

        self::assertSame([null, null, $connection->id, null, null], [$context->ip, $context->userAgent, $context->connectionId, $context->connectionTenantId, $context->protocol]);
    }
}
