<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\DomainEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure;
use SineMacula\Laravel\Sso\Events\DomainClaimed;
use SineMacula\Laravel\Sso\Events\DomainLapsed;
use SineMacula\Laravel\Sso\Events\DomainRecheckFailed;
use SineMacula\Laravel\Sso\Events\DomainRemoved;
use SineMacula\Laravel\Sso\Events\DomainRestored;
use SineMacula\Laravel\Sso\Events\DomainVerified;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Models\Connection;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the reporter of a domain's lifecycle (SSO-3.2, SSO-3.3,
 * SSO-10.3, SSO-10.4): each event dispatched once, built through the one
 * projection with the connection, its tenant and protocol, the acting identity
 * where one acted, and the IP address and user agent of the client the helper
 * was given, never those of the request being served.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainEvents::class)]
final class DomainEventsTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesDomains;

    /** @var string The IP address of the client the helper is given. */
    private const string IP = '203.0.113.7';

    /** @var string The user agent of the client the helper is given. */
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
     * A claim, a verification and a removal are each reported once, with the
     * acting identity and the client the helper was given.
     *
     * @return void
     */
    public function testReportsTheAdministratorsChangesWithTheirClient(): void
    {
        $connection = $this->makeConnection(['protocol' => 'saml2']);
        $pending    = $this->makeDomain($connection, 'example.com');
        $verified   = $this->makeDomain($connection, 'example.org', ['state' => DomainState::VERIFIED]);
        $actor      = new ActingIdentity('App\Models\User', '42');
        $events     = app(DomainEvents::class);

        $events->claimed($connection, $pending, $actor, self::client());
        $events->verified($connection, $verified, $actor, self::client());
        $events->removed($connection, $verified, $actor, self::client());

        $this->assertEventSequence([DomainClaimed::class, DomainVerified::class, DomainRemoved::class]);

        [$claimed, $verifiedEvent, $removed] = $this->recordedEvents();

        self::assertInstanceOf(DomainClaimed::class, $claimed);
        self::assertSame([$pending->id, 'example.com', '2026-11-08T09:30:00+00:00'], [$claimed->domainId, $claimed->domain, $claimed->pendingExpiresAt->toAtomString()]);
        self::assertInstanceOf(DomainVerified::class, $verifiedEvent);
        self::assertSame([$verified->id, 'example.org'], [$verifiedEvent->domainId, $verifiedEvent->domain]);
        self::assertInstanceOf(DomainRemoved::class, $removed);
        self::assertSame([$verified->id, 'example.org', DomainState::VERIFIED], [$removed->domainId, $removed->domain, $removed->state]);

        foreach ([$claimed, $verifiedEvent, $removed] as $event) {
            self::assertContextOf($event, $connection, '42');
        }
    }

    /**
     * The scheduled checks are reported once each, with no acting identity and
     * the client the helper was given.
     *
     * @return void
     */
    public function testReportsTheScheduledChecksWithTheirClient(): void
    {
        $connection = $this->makeConnection(['protocol' => 'saml2']);
        $domain     = $this->makeDomain($connection, 'example.com', ['state' => DomainState::VERIFIED, 'lapses_at' => CarbonImmutable::parse('2026-11-04T09:30:00Z')]);
        $events     = app(DomainEvents::class);

        $events->recheckFailed($connection, $domain, RecheckFailure::RECORD_ABSENT, self::client());
        $events->restored($connection, $domain, self::client());
        $events->lapsed($connection, $domain, self::client());

        $this->assertEventSequence([DomainRecheckFailed::class, DomainRestored::class, DomainLapsed::class]);

        [$failed, $restored, $lapsed] = $this->recordedEvents();

        self::assertInstanceOf(DomainRecheckFailed::class, $failed);
        self::assertSame([$domain->id, 'example.com', RecheckFailure::RECORD_ABSENT], [$failed->domainId, $failed->domain, $failed->failure]);
        self::assertInstanceOf(DomainRestored::class, $restored);
        self::assertSame([$domain->id, 'example.com'], [$restored->domainId, $restored->domain]);
        self::assertInstanceOf(DomainLapsed::class, $lapsed);
        self::assertSame([$domain->id, 'example.com'], [$lapsed->domainId, $lapsed->domain]);

        foreach ([$failed, $restored, $lapsed] as $event) {
            self::assertContextOf($event, $connection, null);
        }
    }

    /**
     * Work with no client, as the scheduled recheck passes, reports no IP
     * address and no user agent.
     *
     * @return void
     */
    public function testNoClientReportsNoAddressOrUserAgent(): void
    {
        $connection = $this->makeConnection();
        $domain     = $this->makeDomain($connection, 'example.com', ['state' => DomainState::VERIFIED]);

        app(DomainEvents::class)->lapsed($connection, $domain, new ClientContext(null, null));

        $event = $this->recordedEvents()[0] ?? null;

        self::assertInstanceOf(DomainLapsed::class, $event);
        self::assertSame([null, null, $connection->id], [$event->context()->ip, $event->context()->userAgent, $event->context()->connectionId]);
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
     * Assert the event's context names the connection, its tenant and protocol,
     * the acting identity's id and the client given.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?string  $actorId
     * @return void
     */
    private static function assertContextOf(SsoEvent $event, Connection $connection, ?string $actorId): void
    {
        $context = $event->context();

        self::assertSame(
            [self::IP, self::USER_AGENT, $connection->id, 'tenant-1', $connection->protocol, $actorId],
            [$context->ip, $context->userAgent, $context->connectionId, $context->connectionTenantId, $context->protocol, $context->actingIdentityId],
        );
    }
}
