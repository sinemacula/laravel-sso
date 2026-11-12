<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\MetadataEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\MetadataRefreshed;
use SineMacula\Laravel\Sso\Events\MetadataRefreshFailed;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the metadata refresh event reporter.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataEvents::class)]
final class MetadataEventsTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /**
     * Bind a fixed clock and a request from another client, create the tables
     * and record events.
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
     * A requested refresh is reported once with the acting identity and its
     * client.
     *
     * @return void
     */
    public function testReportsARefreshWithItsClient(): void
    {
        $connection = $this->makeConnection(['protocol' => 'saml2']);

        app(MetadataEvents::class)->refreshed(
            $connection,
            ['sso_url', 'sso_url', 'idp_signing_certificates'],
            4,
            true,
            new Caller(new IdentityReference('App\Models\User', '42')),
            new ClientContext('203.0.113.7', 'Example/1.0'),
        );

        $this->assertEventSequence([MetadataRefreshed::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(MetadataRefreshed::class, $event);
        self::assertSame([['sso_url', 'idp_signing_certificates'], 4, true], [$event->changedSettings, $event->metadataVersion, $event->trustChanged]);
        self::assertSame(
            ['203.0.113.7', 'Example/1.0', $connection->id, 'tenant-1', 'saml2', '42'],
            [
                $event->context->ip,
                $event->context->userAgent,
                $event->context->connectionId,
                $event->context->connectionTenantId,
                $event->context->protocol,
                $event->context->actingIdentityId,
            ],
        );
    }

    /**
     * A failed scheduled refresh is reported with no acting identity and no
     * client.
     *
     * @return void
     */
    public function testReportsAFailureOfTheScheduleWithNoClient(): void
    {
        $connection = $this->makeConnection(['protocol' => 'saml2']);

        app(MetadataEvents::class)->refreshFailed(
            $connection,
            FailureReason::FETCH_FAILED,
            2,
            CarbonImmutable::parse('2026-11-01T12:00:00+02:00'),
            null,
            new ClientContext(null, null),
        );

        $this->assertEventSequence([MetadataRefreshFailed::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(MetadataRefreshFailed::class, $event);
        self::assertSame([FailureReason::FETCH_FAILED, 2, '2026-11-01T10:00:00+00:00'], [$event->reason, $event->failures, $event->nextAttemptAt?->toAtomString()]);
        self::assertSame([null, null, $connection->id, null], [$event->context->ip, $event->context->userAgent, $event->context->connectionId, $event->context->actingIdentityId]);
    }

    /**
     * An administrator's failed refresh carries the client.
     *
     * @return void
     */
    public function testReportsAnAdministratorsFailureWithItsClient(): void
    {
        $connection = $this->makeConnection(['protocol' => 'saml2']);

        app(MetadataEvents::class)->refreshFailed(
            $connection,
            FailureReason::METADATA_CONFLICT,
            0,
            null,
            new Caller(new IdentityReference('App\Models\User', '42')),
            new ClientContext('203.0.113.7', 'Example/1.0'),
        );

        $event = $this->recordedEvents()[0] ?? null;

        self::assertInstanceOf(MetadataRefreshFailed::class, $event);
        self::assertNull($event->nextAttemptAt);
        self::assertSame(['203.0.113.7', 'Example/1.0', '42'], [$event->context->ip, $event->context->userAgent, $event->context->actingIdentityId]);
    }
}
