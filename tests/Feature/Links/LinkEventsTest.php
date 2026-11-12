<?php

declare(strict_types = 1);

namespace Tests\Feature\Links;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\LinkActivated;
use SineMacula\Laravel\Sso\Events\LinkConfirmed;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\LinkRemoved;
use SineMacula\Laravel\Sso\Events\LinkSuspended;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkEvents;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the link lifecycle events.
 *
 * The client is the one the change was made for, never the request's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkEvents::class)]
final class LinkEventsTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /** @var string The IP address of the client the helper is given. */
    private const string IP = '203.0.113.7';

    /** @var string The user agent of the client the helper is given. */
    private const string USER_AGENT = 'Example/1.0';

    /**
     * Bind a fixed clock and a request from another client, and record events.
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
     * A created link is reported once with its origin, flow, identity and
     * client.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testReportsALinkCreatedWithItsClient(): void
    {
        $connection = $this->makeConnection();
        $identity   = new IdentityReference('App\Models\User', '7');
        $reference  = RequestReference::generate();
        $events     = app(LinkEvents::class);

        $events->created($connection, $identity, LinkOrigin::LINK_PURPOSE, self::client(), null, 'web', Purpose::LINK, $reference);
        $events->created($connection, $identity, LinkOrigin::MIGRATION, self::client(), new Caller(new IdentityReference('App\Models\Admin', '3')));

        $this->assertEventSequence([LinkCreated::class, LinkCreated::class]);

        [$byFlow, $byAdministrator] = $this->recordedEvents();

        self::assertInstanceOf(LinkCreated::class, $byFlow);
        self::assertSame(LinkOrigin::LINK_PURPOSE, $byFlow->origin);
        self::assertSame(
            ['web', 'link', $reference->value, null],
            [$byFlow->context->application, $byFlow->context->purpose, $byFlow->context->requestReference, $byFlow->context->actingIdentityId],
        );
        self::assertInstanceOf(LinkCreated::class, $byAdministrator);
        self::assertSame([LinkOrigin::MIGRATION, '3', null], [$byAdministrator->origin, $byAdministrator->context->actingIdentityId, $byAdministrator->context->purpose]);

        foreach ([$byFlow, $byAdministrator] as $event) {
            self::assertClientAndConnection($event, $connection->id);
        }
    }

    /**
     * A removed link is reported once with the identity, actor and client.
     *
     * @return void
     */
    public function testReportsALinkRemovedWithItsClient(): void
    {
        $connection = $this->makeConnection();

        app(LinkEvents::class)->removed($connection, new IdentityReference('App\Models\User', '7'), self::client(), new Caller(new IdentityReference('App\Models\Admin', '3')));

        $this->assertEventSequence([LinkRemoved::class]);

        $event = $this->recordedEvents()[0];

        self::assertClientAndConnection($event, $connection->id);
        self::assertSame(['7', '3'], [$event->context()->identityId, $event->context()->actingIdentityId]);
    }

    /**
     * An activated reservation is reported as a domain link, then as activated.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testReportsAnActivationWithItsClient(): void
    {
        $connection = $this->makeConnection();
        $reference  = RequestReference::generate();

        app(LinkEvents::class)->activated($connection, new IdentityReference('App\Models\User', '7'), 'link-1', 'web', $reference, self::client());

        $this->assertEventSequence([LinkCreated::class, LinkActivated::class]);

        [$created, $activated] = $this->recordedEvents();

        self::assertInstanceOf(LinkCreated::class, $created);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $created->origin);
        self::assertInstanceOf(LinkActivated::class, $activated);
        self::assertSame('link-1', $activated->linkId);

        foreach ([$created, $activated] as $event) {
            self::assertClientAndConnection($event, $connection->id);
            self::assertSame(
                ['web', 'sign_in', $reference->value, '7'],
                [$event->context()->application, $event->context()->purpose, $event->context()->requestReference, $event->context()->identityId],
            );
        }
    }

    /**
     * A confirmed link is reported once under the `link` purpose.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testReportsAConfirmationWithItsClient(): void
    {
        $connection = $this->makeConnection();
        $reference  = RequestReference::generate();
        $events     = app(LinkEvents::class);

        $events->confirmed($connection, new IdentityReference('App\Models\User', '7'), self::client(), 'web', $reference);
        $events->confirmed($connection, new IdentityReference('App\Models\User', '7'), self::client());

        $this->assertEventSequence([LinkConfirmed::class, LinkConfirmed::class]);

        [$withFlow, $withoutFlow] = $this->recordedEvents();

        self::assertSame(['web', 'link', $reference->value], [$withFlow->context()->application, $withFlow->context()->purpose, $withFlow->context()->requestReference]);
        self::assertSame([null, 'link', null], [$withoutFlow->context()->application, $withoutFlow->context()->purpose, $withoutFlow->context()->requestReference]);

        foreach ([$withFlow, $withoutFlow] as $event) {
            self::assertClientAndConnection($event, $connection->id);
        }
    }

    /**
     * A suspended link is reported once, without client details when none.
     *
     * @return void
     */
    public function testReportsASuspension(): void
    {
        $events = app(LinkEvents::class);

        $events->suspended('01jbexampleconnection00000', 'tenant-1', 'saml2', new IdentityReference('App\Models\User', '7'), self::client());
        $events->suspended('01jbexampleconnection00000', 'tenant-1', 'saml2', new IdentityReference('App\Models\User', '7'), new ClientContext(null, null));

        $this->assertEventSequence([LinkSuspended::class, LinkSuspended::class]);

        [$withClient, $withoutClient] = $this->recordedEvents();

        self::assertClientAndConnection($withClient, '01jbexampleconnection00000');
        self::assertSame(['saml2', '7'], [$withClient->context()->protocol, $withClient->context()->identityId]);
        self::assertSame(
            [null, null, '01jbexampleconnection00000'],
            [$withoutClient->context()->ip, $withoutClient->context()->userAgent, $withoutClient->context()->connectionId],
        );
    }

    /**
     * The client every report is made for.
     *
     * @return \SineMacula\Laravel\Sso\Http\ClientContext
     */
    private static function client(): ClientContext
    {
        return new ClientContext(self::IP, self::USER_AGENT);
    }

    /**
     * Assert the context carries the client and names the connection and
     * tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @param  string  $connectionId
     * @return void
     */
    private static function assertClientAndConnection(SsoEvent $event, string $connectionId): void
    {
        $context = $event->context();

        self::assertSame([self::IP, self::USER_AGENT, $connectionId, 'tenant-1'], [$context->ip, $context->userAgent, $context->connectionId, $context->connectionTenantId]);
    }
}
