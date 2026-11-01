<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\ConnectionCreated;
use SineMacula\Laravel\Sso\Events\ConnectionDeleted;
use SineMacula\Laravel\Sso\Events\ConnectionDisabled;
use SineMacula\Laravel\Sso\Events\ConnectionEnabled;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\KeyAdded;
use SineMacula\Laravel\Sso\Events\KeyMadeCurrent;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;
use SineMacula\Laravel\Sso\Events\KeyRetired;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;

/**
 * Unit tests for the nine administration events (SSO-10.3, SSO-10.4): each is a
 * package event returning its context, survives a queue unchanged, and holds
 * exactly its declared public properties, none of them a secret, a private key,
 * a setting value or the settings; a connection update holds the names of what
 * changed and nothing else.
 *
 * Disabling and deleting a connection have no management helper until BL-37, so
 * their events are covered here and by the reporter's own test only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionCreated::class)]
#[CoversClass(ConnectionUpdated::class)]
#[CoversClass(ConnectionEnabled::class)]
#[CoversClass(ConnectionDisabled::class)]
#[CoversClass(ConnectionDeleted::class)]
#[CoversClass(KeyAdded::class)]
#[CoversClass(KeyMadeCurrent::class)]
#[CoversClass(KeyRetired::class)]
#[CoversClass(KeyNearingExpiry::class)]
final class AdministrationEventClassesTest extends TestCase
{
    /** @var list<string> Names no administration event may give a property, compared without case or underscores. */
    private const array FORBIDDEN = ['secret', 'privatekey', 'value', 'settings'];

    /** @var string The key's fingerprint the events carry. */
    private const string FINGERPRINT = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /**
     * Each administration event, with the public properties it declares, in
     * order.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Contracts\SsoEvent, 1: list<string>}>
     */
    public static function provideEvents(): iterable
    {
        $context  = self::context();
        $notAfter = CarbonImmutable::parse('2027-11-01T09:30:00Z');

        yield 'connection created' => [new ConnectionCreated($context), ['context']];
        yield 'connection updated' => [new ConnectionUpdated($context, ['token_endpoint', 'client_secret', 'display_name']), ['context', 'changedSettings']];
        yield 'connection enabled' => [new ConnectionEnabled($context), ['context']];
        yield 'connection disabled' => [new ConnectionDisabled($context), ['context']];
        yield 'connection deleted' => [new ConnectionDeleted($context), ['context']];
        yield 'key added' => [
            new KeyAdded($context, '01jbkey0000000000000000001', KeyUse::SP_SIGNING, KeyState::NEXT, self::FINGERPRINT, $notAfter),
            ['context', 'keyId', 'use', 'state', 'fingerprint', 'notAfter'],
        ];
        yield 'certificate added' => [
            new KeyAdded($context, '01jbkey0000000000000000002', KeyUse::IDP_SIGNING, null, self::FINGERPRINT, null),
            ['context', 'keyId', 'use', 'state', 'fingerprint', 'notAfter'],
        ];
        yield 'key made current' => [
            new KeyMadeCurrent($context, '01jbkey0000000000000000001', KeyUse::CLIENT_ASSERTION, self::FINGERPRINT, '01jbkey0000000000000000003'),
            ['context', 'keyId', 'use', 'fingerprint', 'previousKeyId'],
        ];
        yield 'key retired' => [new KeyRetired($context, '01jbkey0000000000000000003', KeyUse::SP_ENCRYPTION, self::FINGERPRINT), ['context', 'keyId', 'use', 'fingerprint']];
        yield 'key nearing expiry' => [
            new KeyNearingExpiry($context, '01jbkey0000000000000000002', KeyUse::IDP_SIGNING, self::FINGERPRINT, $notAfter),
            ['context', 'keyId', 'use', 'fingerprint', 'notAfter'],
        ];
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
     * event: every property holds the same value, and the context the same
     * record.
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
        self::assertNotSame($event, $restored);
        self::assertEquals($event, $restored);
        self::assertSame($event->context()->toArray(), $restored->context()->toArray());

        foreach ($properties as $name) {

            $before = (new \ReflectionProperty($event, $name))->getValue($event);
            $after  = (new \ReflectionProperty($restored, $name))->getValue($restored);

            if ($before instanceof \UnitEnum || is_scalar($before) || is_array($before) || $before === null) {
                self::assertSame($before, $after, sprintf('%s::$%s changed across the queue.', $event::class, $name));
                continue;
            }

            self::assertEquals($before, $after, sprintf('%s::$%s changed across the queue.', $event::class, $name));
        }
    }

    /**
     * By reflection, each event holds exactly the public properties it
     * declares, each read-only, and none named after a secret, a private key, a
     * value or the settings.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @param  list<string>  $properties
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEachHoldsExactlyItsDeclaredProperties(SsoEvent $event, array $properties): void
    {
        $declared = (new \ReflectionClass($event))->getProperties();
        $names    = array_map(static fn (\ReflectionProperty $property): string => $property->getName(), $declared);

        self::assertSame($properties, $names);

        foreach ($declared as $property) {

            $normalized = strtolower(str_replace('_', '', $property->getName()));

            self::assertTrue($property->isPublic(), sprintf('%s::$%s is not public.', $event::class, $property->getName()));
            self::assertTrue($property->isReadOnly(), sprintf('%s::$%s is not read-only.', $event::class, $property->getName()));
            self::assertFalse($property->isStatic(), sprintf('%s::$%s is static.', $event::class, $property->getName()));
            self::assertNotContains($normalized, self::FORBIDDEN, sprintf('%s holds a property named %s.', $event::class, $property->getName()));
        }
    }

    /**
     * A connection update holds the names of what changed, as a list of
     * strings, and nothing of their values.
     *
     * @return void
     */
    public function testConnectionUpdatedHoldsAListOfNamesOnly(): void
    {
        $names = ['token_endpoint', 'client_secret', 'display_name', 'attribute_mapping'];
        $event = new ConnectionUpdated(self::context(), $names);

        $type = (new \ReflectionProperty(ConnectionUpdated::class, 'changedSettings'))->getType();

        self::assertInstanceOf(\ReflectionNamedType::class, $type);
        self::assertSame('array', $type->getName());
        self::assertSame($names, $event->changedSettings);
        self::assertTrue(array_is_list($event->changedSettings));

        foreach ($event->changedSettings as $name) {
            self::assertIsString($name);
            self::assertMatchesRegularExpression('/^[a-z][a-z0-9_]*$/', $name);
        }

        $restored = unserialize(serialize($event));

        self::assertInstanceOf(ConnectionUpdated::class, $restored);
        self::assertSame($names, $restored->changedSettings);
    }

    /**
     * A context of an administration change, by an acting identity.
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
            tenantId: 'tenant_1',
            protocol: 'saml2',
            actingIdentityMorphClass: 'App\Models\User',
            actingIdentityId: '42',
        );
    }
}
