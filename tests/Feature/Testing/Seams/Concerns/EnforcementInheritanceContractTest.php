<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing\Seams\Concerns;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Testing\Seams\Concerns\EnforcementInheritanceContract;
use Tests\Concerns\UsesEnforcement;
use Tests\Fixtures\Enforcement\NearestRuleInheritance;
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
    use EnforcementInheritanceContract, UsesEnforcement;

    /** @var array<string, string> Each tenant with a parent, and that parent. */
    public const array PARENTS = ['acme-eu' => 'Acme'];

    /** @var ?string How the binding breaks the contract, if it does. */
    private ?string $flaw = null;

    /**
     * Store `Acme`'s rule, which `acme-eu` inherits.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->usePackageTables();
        $this->makeEnforcement(['tenant_id' => 'Acme']);
    }

    /**
     * Each flaw, with the kit test that catches it.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function flaws(): iterable
    {
        yield 'a folded case' => ['case', 'path'];
        yield 'another answer inside a transaction' => ['transaction', 'path'];
        yield 'a question off the path' => ['off-path', 'questions'];
        yield 'a swallowed question' => ['swallow', 'questions'];
    }

    /**
     * The kit fails a binding that breaks the contract.
     *
     * @param  string  $flaw
     * @param  string  $kitTest
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('flaws')]
    public function testCatchesABrokenBinding(string $flaw, string $kitTest): void
    {
        $this->flaw = $flaw;

        $this->expectException(AssertionFailedError::class);

        match ($kitTest) {
            'path'      => $this->testEnforcementInheritanceAnswersEachTenantsPath(),
            'questions' => $this->testEnforcementInheritanceAsksOnlyOfItsPath(),
        };
    }

    /**
     * A nearest-rule binding over a fixed tree, broken as the test says.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\EnforcementInheritance
     */
    #[\Override]
    protected function enforcementInheritance(): EnforcementInheritance
    {
        return new readonly class ($this->flaw, new NearestRuleInheritance(self::PARENTS)) implements EnforcementInheritance {
            /**
             * Constructor.
             *
             * @param  ?string  $flaw
             * @param  \SineMacula\Laravel\Sso\Contracts\EnforcementInheritance  $tree
             */
            public function __construct(

                /** How the binding breaks the contract, if it does. */
                private ?string $flaw,

                /** The binding that keeps the contract. */
                private EnforcementInheritance $tree,
            ) {}

            /**
             * The tree's answer, broken as the flaw says.
             *
             * @param  string  $tenantId
             * @param  string  $application
             * @param  \Closure(string): bool  $isConfigured
             * @return non-empty-list<string>
             */
            #[\Override]
            public function enforcementPath(string $tenantId, string $application, \Closure $isConfigured): array
            {
                $asked = $this->flaw === 'off-path' ? static fn (string $id): bool => $isConfigured('elsewhere') || $isConfigured($id) : $isConfigured;
                $path  = $this->flaw === 'swallow' ? $this->swallowing($tenantId, $application, $asked) : $this->tree->enforcementPath($tenantId, $application, $asked);

                return match (true) {
                    $this->flaw === 'case'                                                    => array_map(strtolower(...), $path),
                    $this->flaw === 'transaction' && DB::connection()->transactionLevel() > 0 => [$tenantId],
                    default                                                                   => $path,
                };
            }

            /**
             * The tree's answer, or the tenant alone when the question threw.
             *
             * @param  string  $tenantId
             * @param  string  $application
             * @param  \Closure(string): bool  $isConfigured
             * @return non-empty-list<string>
             */
            private function swallowing(string $tenantId, string $application, \Closure $isConfigured): array
            {
                try {
                    return $this->tree->enforcementPath($tenantId, $application, $isConfigured);
                } catch (\Throwable) {
                    return [$tenantId];
                }
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
     * @return array<string, non-empty-list<string>>
     */
    #[\Override]
    protected function inheritancePaths(): array
    {
        return ['Acme' => ['Acme'], 'acme-eu' => ['acme-eu', 'Acme'], 'other' => ['other']];
    }
}
