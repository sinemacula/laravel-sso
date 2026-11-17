<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure;
use SineMacula\Laravel\Sso\Events\DomainClaimed;
use SineMacula\Laravel\Sso\Events\DomainLapsed;
use SineMacula\Laravel\Sso\Events\DomainRecheckFailed;
use SineMacula\Laravel\Sso\Events\DomainRemoved;
use SineMacula\Laravel\Sso\Events\DomainRestored;
use SineMacula\Laravel\Sso\Events\DomainVerified;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\ExemptionUsed;

/**
 * Unit tests for the domain and enforcement events.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainClaimed::class)]
#[CoversClass(DomainVerified::class)]
#[CoversClass(DomainRecheckFailed::class)]
#[CoversClass(DomainRestored::class)]
#[CoversClass(DomainLapsed::class)]
#[CoversClass(DomainRemoved::class)]
#[CoversClass(EnforcementChanged::class)]
#[CoversClass(ExemptionUsed::class)]
final class DomainAndEnforcementEventClassesTest extends TestCase
{
    /** @var list<string> Forbidden property names, ignoring case and underscores. */
    private const array FORBIDDEN = ['token', 'verificationtoken', 'record', 'records', 'secret', 'value'];

    /** @var string The claim the domain events concern. */
    private const string DOMAIN_ID = '01jbexampledomain000000000';

    /**
     * Each event, with the public properties it declares, in order.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\Sso\Contracts\SsoEvent, 1: list<string>}>
     */
    public static function provideEvents(): iterable
    {
        $context = self::context();
        $at      = CarbonImmutable::parse('2026-11-08T09:30:00Z');

        yield 'domain claimed' => [
            static fn (): SsoEvent => new DomainClaimed($context, self::DOMAIN_ID, 'example.com', '_sso-verification.example.com', $at),
            ['context', 'domainId', 'domain', 'recordName', 'pendingExpiresAt'],
        ];
        yield 'domain verified' => [static fn (): SsoEvent => new DomainVerified($context, self::DOMAIN_ID, 'example.com', $at), ['context', 'domainId', 'domain', 'verifiedAt']];
        yield 'domain recheck failed' => [
            static fn (): SsoEvent => new DomainRecheckFailed($context, self::DOMAIN_ID, 'example.com', RecheckFailure::RECORD_CHANGED, $at),
            ['context', 'domainId', 'domain', 'failure', 'lapsesAt'],
        ];
        yield 'domain recheck failed by a lookup' => [
            static fn (): SsoEvent => new DomainRecheckFailed($context, self::DOMAIN_ID, 'example.com', RecheckFailure::LOOKUP_FAILED, null),
            ['context', 'domainId', 'domain', 'failure', 'lapsesAt'],
        ];
        yield 'domain restored' => [
            static fn (): SsoEvent => new DomainRestored($context, self::DOMAIN_ID, 'example.com', $at, $at),
            ['context', 'domainId', 'domain', 'verifiedAt', 'checkedAt'],
        ];
        yield 'domain lapsed' => [static fn (): SsoEvent => new DomainLapsed($context, self::DOMAIN_ID, 'example.com'), ['context', 'domainId', 'domain']];
        yield 'domain removed' => [
            static fn (): SsoEvent => new DomainRemoved($context, self::DOMAIN_ID, 'example.com', DomainState::VERIFIED),
            ['context', 'domainId', 'domain', 'state'],
        ];
        yield 'enforcement changed' => [
            static fn (): SsoEvent => new EnforcementChanged($context, true, ['01jbconnection000000000001'], '01jbversion000000000000002', '01jbversion000000000000001'),
            ['context', 'enabled', 'connectionIds', 'version', 'previousVersion'],
        ];
        yield 'exemption used' => [static fn (): SsoEvent => new ExemptionUsed($context, '01jbversion000000000000002'), ['context', 'enforcementVersion']];
    }

    /**
     * Each event is a final, read-only package event returning its context.
     *
     * @param  \Closure(): \SineMacula\Laravel\Sso\Contracts\SsoEvent  $make
     * @param  list<string>  $properties
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEachIsAPackageEventReturningItsContext(\Closure $make, array $properties): void
    {
        $event = $make();

        $class = new \ReflectionClass($event);

        self::assertSame('context', $properties[0]);
        self::assertTrue($class->implementsInterface(SsoEvent::class));
        self::assertTrue($class->isFinal());
        self::assertTrue($class->isReadOnly());
        self::assertSame($class->getProperty('context')->getValue($event), $event->context());
    }

    /**
     * A serialise round trip, as a queue makes, gives an equal event.
     *
     * @param  \Closure(): \SineMacula\Laravel\Sso\Contracts\SsoEvent  $make
     * @param  list<string>  $properties
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEachSurvivesASerializeRoundTrip(\Closure $make, array $properties): void
    {
        $event = $make();

        $restored = unserialize(serialize($event));

        self::assertInstanceOf($event::class, $restored);
        self::assertEquals($event, $restored);
        self::assertSame($event->context()->toArray(), $restored->context()->toArray());

        foreach ($properties as $name) {

            $before = (new \ReflectionProperty($event, $name))->getValue($event);
            $after  = (new \ReflectionProperty($restored, $name))->getValue($restored);

            if (is_object($before) && !$before instanceof \UnitEnum) {
                self::assertEquals($before, $after);
                continue;
            }

            self::assertSame($before, $after, sprintf('%s::$%s changed across the queue.', $event::class, $name));
        }
    }

    /**
     * Each event holds exactly its declared properties, none sensitive.
     *
     * @param  \Closure(): \SineMacula\Laravel\Sso\Contracts\SsoEvent  $make
     * @param  list<string>  $properties
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEachHoldsExactlyItsDeclaredProperties(\Closure $make, array $properties): void
    {
        $event = $make();

        $declared = (new \ReflectionClass($event))->getProperties();

        self::assertSame($properties, array_map(static fn (\ReflectionProperty $property): string => $property->getName(), $declared));

        foreach ($declared as $property) {
            self::assertTrue($property->isPublic());
            self::assertTrue($property->isReadOnly());
            self::assertNotContains(strtolower(str_replace('_', '', $property->getName())), self::FORBIDDEN);
        }
    }

    /**
     * A context with every field the projection would give one of these events.
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
            actingIdentityMorphClass: 'App\Models\User',
            actingIdentityId: '42',
        );
    }
}
