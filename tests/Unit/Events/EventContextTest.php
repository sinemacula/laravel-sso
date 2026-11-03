<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\EventContext;

/**
 * Unit tests for the shared event context: every field it holds, as the
 * snake_case record an audit sink keeps, with nothing left unset but `null`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventContext::class)]
final class EventContextTest extends TestCase
{
    /**
     * Every field reaches the record under its name, and the time is an ISO
     * 8601 UTC string to the microsecond, whatever its zone.
     *
     * @return void
     */
    public function testTheRecordHoldsEveryField(): void
    {
        $context = new EventContext(
            occurredAt: CarbonImmutable::parse('2026-10-31 12:00:00.123456', 'Europe/Paris'),
            ip: '203.0.113.7',
            userAgent: 'Example/1.0',
            connectionId: 'conn_1',
            connectionTenantId: 'tenant_1',
            protocol: 'saml2',
            application: 'web',
            purpose: 'sign_in',
            requestReference: 'ref_1',
            identityMorphClass: 'user',
            identityId: '42',
            actingIdentityMorphClass: 'user',
            actingIdentityId: '7',
            principalMorphClass: 'membership',
            principalId: '9',
            tenantId: 'tenant_2',
            sessionId: 'session_1',
            method: 'sso',
        );

        self::assertSame([
            'occurred_at'                 => '2026-10-31T11:00:00.123456Z',
            'ip'                          => '203.0.113.7',
            'user_agent'                  => 'Example/1.0',
            'connection_id'               => 'conn_1',
            'connection_tenant_id'        => 'tenant_1',
            'protocol'                    => 'saml2',
            'application'                 => 'web',
            'purpose'                     => 'sign_in',
            'request_reference'           => 'ref_1',
            'identity_morph_class'        => 'user',
            'identity_id'                 => '42',
            'acting_identity_morph_class' => 'user',
            'acting_identity_id'          => '7',
            'principal_morph_class'       => 'membership',
            'principal_id'                => '9',
            'tenant_id'                   => 'tenant_2',
            'session_id'                  => 'session_1',
            'method'                      => 'sso',
        ], $context->toArray());
    }

    /**
     * A context given only its time holds `null` for everything else, and
     * survives serialisation unchanged.
     *
     * @return void
     */
    public function testAContextOfItsTimeAloneHoldsNullsAndSerializes(): void
    {
        $context = new EventContext(CarbonImmutable::parse('2026-10-31T00:00:00Z'));
        $record  = $context->toArray();

        self::assertSame('2026-10-31T00:00:00.000000Z', $record['occurred_at']);
        self::assertSame([null], array_values(array_unique(array_slice($record, 1))));

        $restored = unserialize(serialize($context));

        self::assertInstanceOf(EventContext::class, $restored);
        self::assertSame($record, $restored->toArray());
    }
}
