<?php

declare(strict_types = 1);

namespace Tests\Unit\Enforcement;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome;
use SineMacula\Laravel\Sso\Enforcement\NoExemptions;
use SineMacula\Laravel\Sso\Enforcement\OwnTenantInheritance;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Revocation\NoSessionRevocation;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * Unit tests for the enforcement contracts' defaults (SSO-4.2, SSO-4.4,
 * SSO-4.5): each tenant's own setting applies to it alone, nobody is exempt,
 * and the session revocation revokes nothing and succeeds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OwnTenantInheritance::class)]
#[CoversClass(NoExemptions::class)]
#[CoversClass(NoSessionRevocation::class)]
#[CoversClass(ExemptionOutcome::class)]
final class EnforcementDefaultsTest extends TestCase
{
    /**
     * The tenant's own setting applies, whatever the application.
     *
     * @return void
     */
    public function testEachTenantsOwnSettingApplies(): void
    {
        $inheritance = new OwnTenantInheritance;

        self::assertSame('tenant-1', $inheritance->enforcingTenant('tenant-1', 'web'));
        self::assertSame('Tenant-1', $inheritance->enforcingTenant('Tenant-1', 'mobile'));
    }

    /**
     * Nobody is exempt.
     *
     * @return void
     */
    public function testNobodyIsExempt(): void
    {
        $outcome = (new NoExemptions)->exemption(
            EnforcementPolicy::required('tenant-1', 'tenant-1', ['c-1'], 'v1'),
            'web',
            new IdentityReference('App\Models\User', '1'),
        );

        self::assertSame(ExemptionOutcome::NOT_EXEMPT, $outcome);
        self::assertFalse($outcome->isExempt());
        self::assertTrue(ExemptionOutcome::EXEMPT->isExempt());
        self::assertSame(['exempt', 'not_exempt'], array_column(ExemptionOutcome::cases(), 'value'));
    }

    /**
     * The default revocation revokes nothing and returns, for every scope.
     *
     * @return void
     */
    public function testTheDefaultRevocationRevokesNothing(): void
    {
        $revocation = new NoSessionRevocation;

        $revocation->revoke(RevocationScope::tenant(EnforcementPolicy::required('tenant-1', 'tenant-1', ['c-1'], 'v1')));
        $revocation->revoke(RevocationScope::identityInConnection('tenant-1', 'c-1', new IdentityReference('App\Models\User', '1'), 'link-1'));

        $this->addToAssertionCount(1);
    }
}
