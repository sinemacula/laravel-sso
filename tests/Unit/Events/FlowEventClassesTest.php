<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\LinkRemoved;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;

/**
 * Unit tests for the flow and link events.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequestStarted::class)]
#[CoversClass(ResultVerified::class)]
#[CoversClass(HandoffIssued::class)]
#[CoversClass(HandoffRedeemed::class)]
#[CoversClass(LinkCreated::class)]
#[CoversClass(LinkRemoved::class)]
final class FlowEventClassesTest extends TestCase
{
    /** @var list<string> Forbidden property names, ignoring case and underscores. */
    private const array FORBIDDEN = ['code', 'handoffcode', 'verifier', 'state', 'nonce', 'subject', 'attributes', 'result', 'assertion', 'token'];

    /**
     * Each event, with the public properties it declares, in order.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Contracts\SsoEvent, 1: list<string>}>
     */
    public static function provideEvents(): iterable
    {
        $context = self::context();

        yield 'authorisation request started' => [new AuthorizationRequestStarted($context), ['context']];
        yield 'result verified' => [new ResultVerified($context), ['context']];
        yield 'handoff issued' => [new HandoffIssued($context), ['context']];
        yield 'handoff redeemed' => [new HandoffRedeemed($context), ['context']];
        yield 'link created' => [new LinkCreated($context, LinkOrigin::VERIFIED_DOMAIN), ['context', 'origin']];
        yield 'link removed' => [new LinkRemoved($context), ['context']];
    }

    /**
     * Each event is a final, read-only package event with these properties.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @param  list<string>  $properties
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testIsAFinalReadOnlyPackageEvent(SsoEvent $event, array $properties): void
    {
        $class = new \ReflectionClass($event);

        self::assertTrue($class->isFinal());
        self::assertTrue($class->isReadOnly());
        self::assertSame(self::context()->toArray(), $event->context()->toArray());
        self::assertSame($properties, array_map(static fn (\ReflectionProperty $property): string => $property->getName(), $class->getProperties(\ReflectionProperty::IS_PUBLIC)));

        foreach ($properties as $property) {
            self::assertNotContains(strtolower(str_replace('_', '', $property)), self::FORBIDDEN);
        }
    }

    /**
     * Each event survives a queue unchanged.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @param  list<string>  $properties
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testSurvivesAQueue(SsoEvent $event, array $properties): void
    {
        self::assertNotSame([], $properties);

        $copy = unserialize(serialize($event));

        self::assertInstanceOf($event::class, $copy);
        self::assertSame($event->context()->toArray(), $copy->context()->toArray());
        self::assertEquals(get_object_vars($event), get_object_vars($copy));
    }

    /**
     * A link created carries how it was made.
     *
     * @return void
     */
    public function testALinkCreatedCarriesItsOrigin(): void
    {
        self::assertSame(LinkOrigin::PROVISIONING, (new LinkCreated(self::context(), LinkOrigin::PROVISIONING))->origin);
    }

    /**
     * A context naming a flow.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    private static function context(): EventContext
    {
        return new EventContext(
            occurredAt: CarbonImmutable::parse('2026-11-01T10:00:00Z'),
            connectionId: '01jbexampleconnection00000',
            connectionTenantId: 'tenant-1',
            protocol: 'oidc',
            application: 'web',
            purpose: 'sign_in',
            requestReference: str_repeat('r', 32),
            identityMorphClass: 'user',
            identityId: '1',
        );
    }
}
