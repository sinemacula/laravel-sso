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
use SineMacula\Laravel\Sso\Events\LinkSuspended;
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
#[CoversClass(LinkSuspended::class)]
final class FlowEventClassesTest extends TestCase
{
    /** @var list<string> Forbidden property names, ignoring case and underscores. */
    private const array FORBIDDEN = ['code', 'handoffcode', 'verifier', 'state', 'nonce', 'subject', 'attributes', 'result', 'assertion', 'token'];

    /**
     * Each event, with the public properties it declares, in order.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\Sso\Contracts\SsoEvent, 1: list<string>}>
     */
    public static function provideEvents(): iterable
    {
        $context = self::context();

        yield 'authorisation request started' => [static fn (): SsoEvent => new AuthorizationRequestStarted($context), ['context']];
        yield 'result verified' => [static fn (): SsoEvent => new ResultVerified($context), ['context']];
        yield 'handoff issued' => [static fn (): SsoEvent => new HandoffIssued($context), ['context']];
        yield 'handoff redeemed' => [static fn (): SsoEvent => new HandoffRedeemed($context), ['context']];
        yield 'link created' => [static fn (): SsoEvent => new LinkCreated('link-1', $context, LinkOrigin::VERIFIED_DOMAIN), ['linkId', 'context', 'origin']];
        yield 'link removed' => [static fn (): SsoEvent => new LinkRemoved('link-1', $context), ['linkId', 'context']];
        yield 'link suspended' => [static fn (): SsoEvent => new LinkSuspended('link-1', $context), ['linkId', 'context']];
    }

    /**
     * Each event is a final, read-only package event with these properties.
     *
     * @param  \Closure(): \SineMacula\Laravel\Sso\Contracts\SsoEvent  $make
     * @param  list<string>  $properties
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testIsAFinalReadOnlyPackageEvent(\Closure $make, array $properties): void
    {
        $event = $make();

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
     * @param  \Closure(): \SineMacula\Laravel\Sso\Contracts\SsoEvent  $make
     * @param  list<string>  $properties
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testSurvivesAQueue(\Closure $make, array $properties): void
    {
        $event = $make();

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
        self::assertSame(LinkOrigin::PROVISIONING, (new LinkCreated('link-1', self::context(), LinkOrigin::PROVISIONING))->origin);
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
