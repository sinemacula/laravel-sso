<?php

declare(strict_types = 1);

namespace Tests\Unit\Enforcement;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;

/**
 * Unit tests for the enforcement policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnforcementPolicy::class)]
final class EnforcementPolicyTest extends TestCase
{
    /**
     * A policy that requires nothing is satisfied by any connection.
     *
     * @return void
     */
    public function testNotRequiredIsSatisfiedByAnyConnection(): void
    {
        $policy = EnforcementPolicy::notRequired('tenant-1', 'parent-1', 'v1');

        self::assertFalse($policy->isRequired());
        self::assertTrue($policy->isSatisfiedBy('any-connection'));
        self::assertSame([], $policy->connectionIds);
        self::assertSame('tenant-1', $policy->tenantId);
        self::assertSame('parent-1', $policy->enforcingTenantId);
        self::assertSame('v1', $policy->version);
        self::assertNull(EnforcementPolicy::notRequired('tenant-1', 'tenant-1')->version);
    }

    /**
     * A required policy is satisfied only by one of its connections.
     *
     * @return void
     */
    public function testRequiredIsSatisfiedOnlyByItsConnections(): void
    {
        $policy = EnforcementPolicy::required('tenant-1', 'tenant-1', ['c-2', 'c-1', 'c-2', ''], 'v2');

        self::assertTrue($policy->isRequired());
        self::assertSame(['c-1', 'c-2'], $policy->connectionIds);
        self::assertTrue($policy->isSatisfiedBy('c-1'));
        self::assertFalse($policy->isSatisfiedBy('C-1'));
        self::assertFalse($policy->isSatisfiedBy('c-3'));
        self::assertFalse(EnforcementPolicy::required('tenant-1', 'tenant-1', [], 'v3')->isSatisfiedBy('c-1'));
    }

    /**
     * Rows of `[build]`: a policy missing its tenants or its required version.
     *
     * @return iterable<string, array{\Closure(): \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy}>
     */
    public static function provideIncompletePolicies(): iterable
    {
        yield 'a required policy without a version' => [static fn (): EnforcementPolicy => EnforcementPolicy::required('tenant-1', 'tenant-1', [], '')];
        yield 'a required policy without its tenant' => [static fn (): EnforcementPolicy => EnforcementPolicy::required('', 'tenant-1', [], 'v1')];
        yield 'a policy without its enforcing tenant' => [static fn (): EnforcementPolicy => EnforcementPolicy::notRequired('tenant-1', '')];
    }

    /**
     * A required policy has a version, and every policy names its tenants.
     *
     * @param  \Closure(): \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $build
     * @return void
     */
    #[DataProvider('provideIncompletePolicies')]
    public function testRefusesAPolicyWithoutItsTenantsOrVersion(\Closure $build): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $build();
    }

    /**
     * The encoding has snake_case keys.
     *
     * @return void
     */
    public function testEncodesWithSnakeCaseKeys(): void
    {
        self::assertSame(
            ['tenant_id' => 'tenant-1', 'enforcing_tenant_id' => 'tenant-1', 'required' => true, 'connection_ids' => ['c-1'], 'version' => 'v1'],
            EnforcementPolicy::required('tenant-1', 'tenant-1', ['c-1'], 'v1')->jsonSerialize(),
        );
    }
}
