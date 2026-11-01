<?php

declare(strict_types = 1);

namespace Tests\Unit\Enforcement;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Enforcement\EnforcementSummary;

/**
 * Unit tests for the summary of a tenant's enforcement: a tenant with no rule
 * stored is off with no connection, version or time; ids are kept each once, in
 * id order, compared byte for byte; and the encoding has snake_case keys and
 * the time in UTC.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnforcementSummary::class)]
final class EnforcementSummaryTest extends TestCase
{
    /**
     * A tenant with no row is off, with no connection, no version and no time.
     *
     * @return void
     */
    public function testATenantWithNoRuleIsOff(): void
    {
        $summary = EnforcementSummary::of('tenant-1', null);

        self::assertSame('tenant-1', $summary->tenantId);
        self::assertFalse($summary->enabled);
        self::assertSame([], $summary->connectionIds);
        self::assertNull($summary->version);
        self::assertNull($summary->changedAt);
        self::assertSame(['tenant_id' => 'tenant-1', 'enabled' => false, 'connection_ids' => [], 'version' => null, 'changed_at' => null], $summary->jsonSerialize());
    }

    /**
     * The ids are each kept once, in id order, compared byte for byte, and
     * anything but a string is dropped.
     *
     * @return void
     */
    public function testIdsAreKeptOnceInIdOrder(): void
    {
        self::assertSame(['01b', '01c', 'Z1', 'z1'], EnforcementSummary::sorted(['z1', '01c', 'Z1', '01b', '01c', 7, null, ['01d']]));
        self::assertSame([], EnforcementSummary::sorted([]));
    }

    /**
     * The encoding has snake_case keys, the ids as given and the time as an ISO
     * 8601 string in UTC, whatever the time's own zone.
     *
     * @return void
     */
    public function testEncodesTheTimeInUtc(): void
    {
        $changedAt = CarbonImmutable::parse('2026-11-01T11:30:05+02:00');
        $summary   = new EnforcementSummary('Tenant-1', true, ['01a', '01b'], '01jbversion', $changedAt);

        self::assertSame([
            'tenant_id'      => 'Tenant-1',
            'enabled'        => true,
            'connection_ids' => ['01a', '01b'],
            'version'        => '01jbversion',
            'changed_at'     => '2026-11-01T09:30:05Z',
        ], $summary->jsonSerialize());

        self::assertSame('+02:00', $summary->changedAt?->format('P'));
        self::assertSame(
            '{"tenant_id":"Tenant-1","enabled":true,"connection_ids":["01a","01b"],"version":"01jbversion","changed_at":"2026-11-01T09:30:05Z"}',
            json_encode($summary),
        );
    }
}
