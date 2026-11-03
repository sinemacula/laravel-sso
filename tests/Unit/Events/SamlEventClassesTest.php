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
use SineMacula\Laravel\Sso\Events\MetadataRefreshed;
use SineMacula\Laravel\Sso\Events\MetadataRefreshFailed;
use SineMacula\Laravel\Sso\Events\UnsolicitedResponseReinitiated;

/**
 * Unit tests for the events the SAML driver adds (SSO-10.1, SSO-10.3,
 * SSO-10.4): metadata refreshed (with the names of the settings that changed)
 * and failed to refresh (with the reason, the failures in a row and the next
 * attempt), and an unsolicited response re-initiated. Each is a final,
 * read-only package event returning its context, survives a queue unchanged,
 * and holds exactly its declared public properties, none of them metadata, a
 * URL, a certificate, a value or a response.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataRefreshed::class)]
#[CoversClass(MetadataRefreshFailed::class)]
#[CoversClass(UnsolicitedResponseReinitiated::class)]
final class SamlEventClassesTest extends TestCase
{
    /** @var list<string> Names no event here may give a property, compared without case or underscores. */
    private const array FORBIDDEN = ['metadata', 'url', 'certificate', 'value', 'values', 'response', 'assertion', 'relaystate', 'subject'];

    /**
     * Each event, with the public properties it declares, in order.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Contracts\SsoEvent, 1: list<string>}>
     */
    public static function provideEvents(): iterable
    {
        $context = self::context();

        $refreshed = ['context', 'changedSettings', 'metadataVersion', 'trustChanged'];

        yield 'metadata refreshed' => [new MetadataRefreshed($context, ['sso_url', 'idp_signing_certificates'], 4, true), $refreshed];
        yield 'metadata unchanged' => [new MetadataRefreshed($context, [], 3, false), $refreshed];
        yield 'metadata refresh failed' => [
            new MetadataRefreshFailed($context, FailureReason::METADATA_SIGNATURE_INVALID, 3, CarbonImmutable::parse('2026-11-01T10:30:00Z')),
            ['context', 'reason', 'failures', 'nextAttemptAt'],
        ];
        yield 'metadata refresh failed, none scheduled' => [
            new MetadataRefreshFailed($context, FailureReason::FETCH_FAILED, 1, null),
            ['context', 'reason', 'failures', 'nextAttemptAt'],
        ];
        yield 'unsolicited response reinitiated' => [new UnsolicitedResponseReinitiated($context), ['context']];
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
        self::assertSame($event->context()->toArray(), $restored->context()->toArray());

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
     * A refresh failure keeps what it was given exactly.
     *
     * @return void
     */
    public function testARefreshFailureKeepsWhatItWasGiven(): void
    {
        $next  = CarbonImmutable::parse('2026-11-01T10:30:00Z');
        $event = new MetadataRefreshFailed(self::context(), FailureReason::METADATA_CONFLICT, 2, $next);

        self::assertSame([FailureReason::METADATA_CONFLICT, 2, $next], [$event->reason, $event->failures, $event->nextAttemptAt]);
        $refreshed = new MetadataRefreshed(self::context(), ['sso_url'], 2, false);

        self::assertSame([['sso_url'], 2, false], [$refreshed->changedSettings, $refreshed->metadataVersion, $refreshed->trustChanged]);
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
            protocol: 'saml2',
        );
    }
}
