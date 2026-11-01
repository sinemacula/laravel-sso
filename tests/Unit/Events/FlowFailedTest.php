<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\FlowFailed;

/**
 * Unit tests for the failure event: a package event carrying its context, its
 * flow and its reason and nothing else, which survives a queue unchanged.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FlowFailed::class)]
final class FlowFailedTest extends TestCase
{
    /**
     * The event is a package event, and returns the context it was given.
     *
     * @return void
     */
    public function testItIsAPackageEventReturningItsContext(): void
    {
        $context = self::context();
        $event   = new FlowFailed($context, Flow::CALLBACK, FailureReason::NONCE_MISMATCH);

        self::assertTrue((new \ReflectionClass(FlowFailed::class))->implementsInterface(SsoEvent::class));
        self::assertSame($context, $event->context());
        self::assertSame($context, $event->context);
        self::assertSame(Flow::CALLBACK, $event->flow);
        self::assertSame(FailureReason::NONCE_MISMATCH, $event->reason);
    }

    /**
     * A serialise and unserialise round trip, as a queue makes, keeps the flow,
     * the reason and the context.
     *
     * @return void
     */
    public function testItSurvivesASerializeRoundTrip(): void
    {
        $event = new FlowFailed(self::context(), Flow::ASSERTION, FailureReason::REPLAYED);

        $restored = unserialize(serialize($event));

        self::assertInstanceOf(FlowFailed::class, $restored);
        self::assertNotSame($event, $restored);
        self::assertSame(Flow::ASSERTION, $restored->flow);
        self::assertSame(FailureReason::REPLAYED, $restored->reason);
        self::assertSame($event->context()->toArray(), $restored->context()->toArray());
    }

    /**
     * The event holds its context, its flow and its reason, and no other
     * property: no free-text message, no payload.
     *
     * @return void
     */
    public function testItHoldsNothingBeyondItsContextFlowAndReason(): void
    {
        $properties = array_map(
            static fn (\ReflectionProperty $property): string => $property->getName(),
            (new \ReflectionClass(FlowFailed::class))->getProperties(),
        );

        self::assertSame(['context', 'flow', 'reason'], $properties);
    }

    /**
     * A context naming the connection and the request's public reference.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    private static function context(): EventContext
    {
        return new EventContext(
            occurredAt: CarbonImmutable::parse('2026-10-31T12:00:00.123456Z'),
            ip: '203.0.113.7',
            userAgent: 'Example/1.0',
            connectionId: 'conn_1',
            tenantId: 'tenant_1',
            protocol: 'oidc',
            application: 'web',
            purpose: 'sign_in',
            requestReference: 'ref_1',
        );
    }
}
