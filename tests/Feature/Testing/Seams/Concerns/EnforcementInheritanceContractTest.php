<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing\Seams\Concerns;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Testing\Seams\Concerns\EnforcementInheritanceContract;
use Tests\TestCase;

/**
 * Feature tests for the enforcement inheritance kit, run against a binding that
 * keeps it and ones that do not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(EnforcementInheritanceContract::class)]
final class EnforcementInheritanceContractTest extends TestCase
{
    use EnforcementInheritanceContract;

    /** @var array<string, string> Each tenant's enforcing tenant. */
    public const array TREE = ['Acme' => 'Acme', 'acme-eu' => 'Acme', 'other' => 'other'];

    /** @var ?string How the binding breaks the contract, if it does. */
    private ?string $flaw = null;

    /**
     * The kit fails a binding that folds the tenant's case.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCatchesABindingThatFoldsCase(): void
    {
        $this->flaw = 'case';

        $this->expectException(AssertionFailedError::class);

        $this->testEnforcementInheritanceAnswersEachTenantsEnforcingTenant();
    }

    /**
     * The kit fails a binding that answers otherwise inside a transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCatchesABindingThatAnswersOtherwiseInsideATransaction(): void
    {
        $this->flaw = 'transaction';

        $this->expectException(AssertionFailedError::class);

        $this->testEnforcementInheritanceAnswersEachTenantsEnforcingTenant();
    }

    /**
     * A binding over a fixed tree, broken as the test says.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\EnforcementInheritance
     */
    #[\Override]
    protected function enforcementInheritance(): EnforcementInheritance
    {
        return new readonly class ($this->flaw) implements EnforcementInheritance {
            /**
             * Constructor.
             *
             * @param  ?string  $flaw
             */
            public function __construct(

                /** How the binding breaks the contract, if it does. */
                private ?string $flaw,
            ) {}

            /**
             * The tree's answer for the tenant.
             *
             * @param  string  $tenantId
             * @param  string  $application
             * @return string
             */
            #[\Override]
            public function enforcingTenant(string $tenantId, string $application): string
            {
                unset($application);

                return match (true) {
                    $this->flaw === 'case'                                                    => strtolower(EnforcementInheritanceContractTest::TREE[$tenantId]),
                    $this->flaw === 'transaction' && DB::connection()->transactionLevel() > 0 => $tenantId,
                    default                                                                   => EnforcementInheritanceContractTest::TREE[$tenantId],
                };
            }
        };
    }

    /**
     * @return string
     */
    #[\Override]
    protected function inheritanceApplication(): string
    {
        return 'web';
    }

    /**
     * @return array<string, string>
     */
    #[\Override]
    protected function enforcingTenants(): array
    {
        return self::TREE;
    }
}
