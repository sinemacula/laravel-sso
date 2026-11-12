<?php

declare(strict_types = 1);

namespace Tests\Unit\Links;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkSummary;

/**
 * Unit tests for a link summary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkSummary::class)]
final class LinkSummaryTest extends TestCase
{
    /**
     * A used SAML link encodes every part, each time in UTC.
     *
     * @return void
     */
    public function testAUsedLinkEncodesEveryPart(): void
    {
        $summary = new LinkSummary(
            '01jbexamplelink00000000000',
            '01jbexampleconnection00000',
            'tenant-1',
            'saml2',
            'https://idp.example.com',
            'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            LinkState::RESERVED,
            true,
            CarbonImmutable::parse('2026-11-01T10:30:00+01:00'),
            CarbonImmutable::parse('2026-11-01T11:45:30.987654Z'),
        );

        self::assertSame([
            'id'                => '01jbexamplelink00000000000',
            'connection_id'     => '01jbexampleconnection00000',
            'tenant_id'         => 'tenant-1',
            'protocol'          => 'saml2',
            'issuer'            => 'https://idp.example.com',
            'name_id_format'    => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            'state'             => 'reserved',
            'domain_provenance' => true,
            'created_at'        => '2026-11-01T09:30:00Z',
            'last_used_at'      => '2026-11-01T11:45:30Z',
        ], $summary->jsonSerialize());
    }

    /**
     * An unused link encodes nulls and never the subject.
     *
     * @return void
     */
    public function testAnUnusedLinkEncodesNullsAndNoSubject(): void
    {
        $summary = new LinkSummary(
            '01jbexamplelink00000000000',
            '01jbexampleconnection00000',
            'tenant-1',
            'oidc',
            'https://op.example.com',
            null,
            LinkState::ACTIVE,
            false,
            CarbonImmutable::parse('2026-11-01T09:30:00Z'),
        );

        $encoded = $summary->jsonSerialize();

        self::assertNull($summary->lastUsedAt);
        self::assertNull($encoded['name_id_format']);
        self::assertNull($encoded['last_used_at']);
        self::assertSame('active', $encoded['state']);
        self::assertFalse($encoded['domain_provenance']);
        self::assertSame(
            ['id', 'connection_id', 'tenant_id', 'protocol', 'issuer', 'name_id_format', 'state', 'domain_provenance', 'created_at', 'last_used_at'],
            array_keys($encoded),
        );
        self::assertSame(
            '{"id":"01jbexamplelink00000000000","connection_id":"01jbexampleconnection00000","tenant_id":"tenant-1","protocol":"oidc",'
            . '"issuer":"https:\/\/op.example.com","name_id_format":null,"state":"active","domain_provenance":false,'
            . '"created_at":"2026-11-01T09:30:00Z","last_used_at":null}',
            json_encode($summary),
        );
    }
}
