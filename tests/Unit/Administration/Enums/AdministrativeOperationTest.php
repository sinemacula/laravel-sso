<?php

declare(strict_types = 1);

namespace Tests\Unit\Administration\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Administration\Enums\AdministrativeOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * Unit tests for the administrative operation names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdministrativeOperation::class)]
final class AdministrativeOperationTest extends TestCase
{
    /**
     * Every operation is named exactly, in order.
     *
     * @return void
     */
    public function testEveryOperationIsNamedExactly(): void
    {
        self::assertSame([
            'sso.connection.create',
            'sso.connection.update',
            'sso.connection.evidence',
            'sso.connection.linking_policy',
            'sso.connection.import',
            'sso.connection.trust',
            'sso.connection.enable',
            'sso.connection.disable',
            'sso.connection.delete',
            'sso.connection.idp_initiated',
            'sso.connection.migrate_subjects',
            'sso.connection.refresh_metadata',
            'sso.keys.rotate',
            'sso.keys.trust_certificate',
            'sso.keys.distrust_certificate',
            'sso.domain.claim',
            'sso.domain.verify',
            'sso.domain.remove',
            'sso.enforcement.update',
            'sso.link.create',
            'sso.link.remove',
            'sso.link.remove_others',
        ], array_map(static fn (AdministrativeOperation $operation): string => $operation->value, AdministrativeOperation::cases()));
    }

    /**
     * Each freshness operation has an administrative operation of its name.
     *
     * @return void
     */
    public function testEveryFreshnessOperationIsOne(): void
    {
        foreach (FreshnessOperation::cases() as $operation) {
            self::assertNotNull(AdministrativeOperation::tryFrom($operation->value), $operation->value);
        }
    }
}
