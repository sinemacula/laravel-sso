<?php

declare(strict_types = 1);

namespace Tests\Feature\Provisioning;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Clients;

/**
 * Feature tests for the client a provisioning listener links a result for: the
 * `LinkCreated` the helper reports carries the IP address and user agent of the
 * client it was given, never those of the request being served, while the
 * completion's own events carry the completion's client.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProvisioningHelper::class)]
final class ProvisioningHelperTest extends LinkingTestCase
{
    /**
     * Make the result unmatched by any verified domain, so it is offered for
     * provisioning.
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
     * The link the helper creates is reported with the client it was given.
     *
     * @return void
     */
    public function testTheLinkIsReportedWithTheClientGiven(): void
    {
        $client = new ClientContext('192.0.2.44', 'Provisioner/1.0');

        $this->start();

        Event::listen(SsoEvent::class, function (SsoEvent $event) use ($client): void {
            if (!$event instanceof ResultUnlinked) {
                return;
            }

            self::assertTrue(app(ProvisioningHelper::class)->link($event->grant, $event->result, $this->person, $client)->isCreated());
        });

        $this->app?->instance('request', Request::create('/', 'POST', server: ['REMOTE_ADDR' => '198.51.100.9', 'HTTP_USER_AGENT' => 'Served/1.0']));
        $this->startRecordingEvents();

        self::assertTrue($this->complete()->isCompleted());

        $this->assertEventSequence([ResultVerified::class, ResultUnlinked::class, LinkCreated::class, HandoffIssued::class]);

        $created = $this->recordedEvents()[2];

        self::assertInstanceOf(LinkCreated::class, $created);
        self::assertSame(LinkOrigin::PROVISIONING, $created->origin);
        self::assertSame(['192.0.2.44', 'Provisioner/1.0'], [$created->context()->ip, $created->context()->userAgent]);
        self::assertSame($this->person->id, $created->context()->identityId);
        self::assertSame([Clients::IP, Clients::USER_AGENT], [$this->recordedEvents()[0]->context()->ip, $this->recordedEvents()[0]->context()->userAgent]);
    }
}
