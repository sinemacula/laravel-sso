<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\JwksRefreshed;
use SineMacula\Laravel\Sso\Events\JwksRefreshFailed;

/**
 * Unit tests for the events the OIDC driver reports beside the flow and
 * metadata events (SSO-7.3, SSO-10.3, SSO-10.4): each is a final, read-only
 * package event holding its context and exactly its declared properties, none
 * named after a key, URL or token, and each survives a queue's round trip.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwksRefreshed::class)]
#[CoversClass(JwksRefreshFailed::class)]
final class OidcEventClassesTest extends TestCase
{
    /** @var list<string> Names no event here may give a property, compared without case or underscores. */
    private const array FORBIDDEN = ['jwks', 'keys', 'key', 'url', 'jwksuri', 'token', 'idtoken', 'accesstoken', 'value', 'values', 'kid'];

    /**
     * Each event, with the public properties it declares, in order.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Contracts\SsoEvent, 1: list<string>}>
     */
    public static function provideEvents(): iterable
    {
        $context = self::context();

        yield 'jwks refreshed' => [new JwksRefreshed($context, 4, 1, 2, true), ['context', 'jwksVersion', 'keysAdded', 'keysRemoved', 'trustChanged']];
        yield 'jwks refreshed, additive' => [new JwksRefreshed($context, 2, 1, 0, false), ['context', 'jwksVersion', 'keysAdded', 'keysRemoved', 'trustChanged']];
        $next = CarbonImmutable::parse('2026-11-01T09:35:00Z');

        yield 'jwks refresh failed' => [new JwksRefreshFailed($context, FailureReason::JWKS_INVALID, $next), ['context', 'reason', 'nextRefetchAt']];
        yield 'jwks refresh failed, no next' => [new JwksRefreshFailed($context, FailureReason::FETCH_FAILED, null), ['context', 'reason', 'nextRefetchAt']];
    }

    /**
     * Each event is a package event, final and read-only, and returns the
     * context it was given.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @param  list<string>  $properties
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEachIsAPackageEventReturningItsContext(SsoEvent $event, array $properties): void
    {
        $class = new \ReflectionClass($event);

        self::assertSame('context', $properties[0]);
        self::assertTrue($class->implementsInterface(SsoEvent::class));
        self::assertTrue($class->isFinal());
        self::assertTrue($class->isReadOnly());
        self::assertSame($class->getProperty('context')->getValue($event), $event->context());
        self::assertSame('conn_1', $event->context()->connectionId);
    }

    /**
     * A serialise and unserialise round trip, as a queue makes, gives an equal
     * event.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @param  list<string>  $properties
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEachSurvivesASerializeRoundTrip(SsoEvent $event, array $properties): void
    {
        $restored = unserialize(serialize($event));

        self::assertInstanceOf($event::class, $restored);
        self::assertEquals($event, $restored);

        foreach (array_slice($properties, 1) as $name) {
            self::assertEquals((new \ReflectionProperty($event, $name))->getValue($event), (new \ReflectionProperty($restored, $name))->getValue($restored));
        }
    }

    /**
     * Each event holds exactly the public, read-only properties it declares,
     * none named after what it must never carry.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @param  list<string>  $properties
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEachHoldsExactlyItsDeclaredProperties(SsoEvent $event, array $properties): void
    {
        $declared = (new \ReflectionClass($event))->getProperties();

        self::assertSame($properties, array_map(static fn (\ReflectionProperty $property): string => $property->getName(), $declared));

        foreach ($declared as $property) {
            self::assertTrue($property->isPublic() && $property->isReadOnly() && !$property->isStatic(), $property->getName());
            self::assertNotContains(strtolower(str_replace('_', '', $property->getName())), self::FORBIDDEN);
        }
    }

    /**
     * Each keeps what it was given exactly.
     *
     * @return void
     */
    public function testEachKeepsWhatItWasGiven(): void
    {
        $next      = CarbonImmutable::parse('2026-11-01T09:35:00Z');
        $failed    = new JwksRefreshFailed(self::context(), FailureReason::METADATA_CONFLICT, $next);
        $refreshed = new JwksRefreshed(self::context(), 7, 2, 1, true);

        self::assertSame([FailureReason::METADATA_CONFLICT, $next], [$failed->reason, $failed->nextRefetchAt]);
        self::assertSame([7, 2, 1, true], [$refreshed->jwksVersion, $refreshed->keysAdded, $refreshed->keysRemoved, $refreshed->trustChanged]);
    }

    /**
     * The context the events carry.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    private static function context(): EventContext
    {
        return new EventContext(
            occurredAt: CarbonImmutable::parse('2026-11-01T09:30:00.123456Z'),
            ip: '203.0.113.7',
            userAgent: 'Example/1.0',
            connectionId: 'conn_1',
            connectionTenantId: 'tenant_1',
            protocol: 'oidc',
        );
    }
}
