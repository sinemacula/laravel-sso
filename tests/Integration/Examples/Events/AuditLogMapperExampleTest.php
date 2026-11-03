<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Events;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Integration\Examples\ExampleTestCase;
use Tests\Integration\Examples\SiblingStandIns;

/**
 * The `laravel-audit-log` example of `docs/guides/events.md` (SSO-10.4,
 * SSO-12.5), on the shared example harness, against the examples' stand-ins for
 * that sibling's facade, mapper contract, pending record and reference
 * (`Events/AuditLog`), which mirror its real signatures: the service provider
 * maps the package's failed flows through the guide's mapper, so a flow refused
 * for its token's audience is recorded once, under its code, as a failure with
 * its reason, by the person the flow was for, for the connection's tenant, and
 * correlated by the connection and the request's reference; and every event of
 * a flow that succeeds is skipped, by the registration and by the mapper alike.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventContext::class)]
#[CoversClass(FlowFailed::class)]
final class AuditLogMapperExampleTest extends ExampleTestCase
{
    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's OpenID provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person each flow is for. */
    private IdentityReference $person;

    /**
     * Load the stand-ins, forget what an earlier test recorded, register the
     * application's service provider, and make the connection and the person.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        SiblingStandIns::register();
        AuditLog::forget();

        $this->app?->register(AuditLogServiceProvider::class);

        $this->provider     = new FakeOpenIdProvider(clock: $this->clock);
        $this->connectionId = $this->makeOidcConnection($this->provider);
        $this->person       = new IdentityReference(User::class, 'person-1');
    }

    /**
     * Forget what this test recorded.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        AuditLog::forget();

        parent::tearDown();
    }

    /**
     * A `link` refused for its token's audience is recorded once: under its
     * code, as a failure with its reason, with its flow and application, by the
     * person it was for, for the connection's tenant (the event names no active
     * one), correlated by the connection and the request's reference.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAFailedFlowIsRecordedThroughTheMapper(): void
    {
        $this->linkThroughFlow($this->provider, $this->connectionId, $this->person);

        $start    = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start, static fn (FakeIdToken $token): FakeIdToken => $token->with('aud', 'another-client'));
        $recorded = AuditLog::recorded();

        self::assertSame('audience_mismatch', $redirect->error);
        self::assertCount(1, $recorded);
        self::assertSame([
            'code'           => 'sso.flow_failed',
            'outcome'        => 'failure',
            'reason'         => 'audience_mismatch',
            'properties'     => ['flow' => 'callback', 'application' => self::APPLICATION],
            'actor'          => [User::class, 'person-1'],
            'tenant'         => ['tenant', self::TENANT],
            'correlation_id' => "sso:{$this->connectionId}:{$start->reference?->value}",
        ], $recorded[0]->toArray());
    }

    /**
     * A flow that succeeds records nothing: no event of it is a failed flow,
     * and the mapper, handed each of them, skips it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEveryOtherEventIsSkipped(): void
    {
        /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Contracts\SsoEvent> $events */
        $events = new \ArrayObject;

        Event::listen(SsoEvent::class, static function (SsoEvent $event) use ($events): void {
            $events->append($event);
        });

        self::assertTrue($this->linkThroughFlow($this->provider, $this->connectionId, $this->person)->isRedeemed());
        self::assertSame([], AuditLog::recorded());
        self::assertSame(
            ['AuthorizationRequestStarted', 'JwksRefreshed', 'ResultVerified', 'HandoffIssued', 'LinkCreated', 'HandoffRedeemed'],
            array_map(class_basename(...), $events->getArrayCopy()),
        );

        foreach ($events as $event) {
            self::assertNull((new SsoAuditMapper)->map($event, new PendingRecord), $event::class);
        }
    }
}
