<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\EnforcementEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Events\ExemptionUsed;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesEnforcement;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the reporter of enforcement (SSO-4.4, SSO-4.5, SSO-10.3,
 * SSO-10.4): a change of a tenant's rule and an exemption used, each dispatched
 * once with what it concerns and the IP address and user agent of the client
 * the helper was given, never those of the request being served.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnforcementEvents::class)]
final class EnforcementEventsTest extends TestCase
{
    use RecordsEventSequences, UsesEnforcement;

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
     * A change of the rule is reported once, with the rule's connections in id
     * order, the version it replaced, the acting identity and the client.
     *
     * @return void
     */
    public function testReportsAChangeWithItsClient(): void
    {
        $row = $this->makeEnforcement(['enabled' => true, 'connection_ids' => ['c-2', 'c-1'], 'version' => '01jbversion000000000000002']);

        app(EnforcementEvents::class)->changed($row, '01jbversion000000000000001', new ActingIdentity('App\Models\User', '42'), new ClientContext('203.0.113.7', 'Example/1.0'));

        $this->assertEventSequence([EnforcementChanged::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(EnforcementChanged::class, $event);
        self::assertSame([['c-1', 'c-2'], '01jbversion000000000000001'], [$event->connectionIds, $event->previousVersion]);
        self::assertSame(
            ['203.0.113.7', 'Example/1.0', 'tenant-1', 'App\Models\User', '42'],
            [$event->context->ip, $event->context->userAgent, $event->context->connectionTenantId, $event->context->actingIdentityMorphClass, $event->context->actingIdentityId],
        );
    }

    /**
     * An exemption used is reported once, with the tenants, the application,
     * the identity, the session and the client; with no session given, none.
     *
     * @return void
     */
    public function testReportsAnExemptionWithItsClient(): void
    {
        $policy   = EnforcementPolicy::required('child-1', 'parent-1', ['c-1'], '01jbversion000000000000003');
        $identity = new IdentityReference('App\Models\User', '7');
        $events   = app(EnforcementEvents::class);

        $events->exemptionUsed($policy, 'web', $identity, new ClientContext('203.0.113.7', 'Example/1.0'), 'session-9');
        $events->exemptionUsed($policy, 'web', $identity, new ClientContext(null, null));

        $this->assertEventSequence([ExemptionUsed::class, ExemptionUsed::class]);

        [$withSession, $withoutClient] = $this->recordedEvents();

        self::assertInstanceOf(ExemptionUsed::class, $withSession);
        self::assertSame(
            ['203.0.113.7', 'Example/1.0', 'parent-1', 'child-1', 'web', '7', 'session-9'],
            [
                $withSession->context->ip,
                $withSession->context->userAgent,
                $withSession->context->connectionTenantId,
                $withSession->context->tenantId,
                $withSession->context->application,
                $withSession->context->identityId,
                $withSession->context->sessionId,
            ],
        );
        self::assertInstanceOf(ExemptionUsed::class, $withoutClient);
        self::assertSame(
            [null, null, null, '01jbversion000000000000003'],
            [$withoutClient->context->ip, $withoutClient->context->userAgent, $withoutClient->context->sessionId, $withoutClient->enforcementVersion],
        );
    }
}
