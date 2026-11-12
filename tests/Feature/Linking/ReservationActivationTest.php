<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\LinkActivated;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Linking\ReservationActivation;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Link;

/**
 * Feature tests that an activation reports the redeeming client, not the
 * completing one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReservationActivation::class)]
final class ReservationActivationTest extends LinkingTestCase
{
    /**
     * An activation reports the client the redemption was given in
     * `LinkCreated` and `LinkActivated`.
     *
     * @return void
     */
    public function testTheActivationIsReportedWithTheRedeemingClient(): void
    {
        $start      = $this->start();
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted(), (string) $completion->reason?->value);
        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);

        $this->app?->instance('request', Request::create('/', 'POST', server: ['REMOTE_ADDR' => '198.51.100.9', 'HTTP_USER_AGENT' => 'Served/1.0']));
        $this->startRecordingEvents();

        $client   = new ClientContext('192.0.2.44', 'Redeemer/2.0');
        $code     = (string) $completion->handoff?->code->reveal();
        $verifier = (string) $start->verifier?->reveal();
        $answer   = $this->connection->getConnection()->transaction(
            fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $this->connection->id, $code, $verifier, $client),
        );

        self::assertTrue($answer->isRedeemed());
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        $this->assertEventSequence([LinkCreated::class, LinkActivated::class, HandoffRedeemed::class]);

        foreach (array_slice($this->recordedEvents(), 0, 2) as $event) {

            $context = $event->context();

            self::assertSame(['192.0.2.44', 'Redeemer/2.0'], [$context->ip, $context->userAgent], $event::class);
            self::assertSame($this->person->id, $context->identityId);
        }
    }
}
