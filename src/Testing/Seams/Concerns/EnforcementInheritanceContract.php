<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Seams\Concerns;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\EnforcementFinder;
use SineMacula\Laravel\Sso\Exceptions\EnforcementPathChanged;

/**
 * What every `Contracts\EnforcementInheritance` must guarantee, as tests: use
 * it in a test case of the binding and implement the methods it declares.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait EnforcementInheritanceContract
{
    /**
     * Each tenant answers its path byte for byte, asked in turn, then again in
     * reverse inside a transaction on the storage connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEnforcementInheritanceAnswersEachTenantsPath(): void
    {
        $expected = $this->inheritancePaths();
        $tenants  = array_keys($expected);
        $stored   = static fn (string $tenantId): bool => (new EnforcementFinder)->find($tenantId) !== null;
        $asked    = function (array $tenants) use ($stored): array {

            $answers = [];

            foreach ($tenants as $tenant) {
                $answers[$tenant] = $this->enforcementInheritance()->enforcementPath((string) $tenant, $this->inheritanceApplication(), $stored);
            }

            ksort($answers, SORT_STRING);

            return $answers;
        };

        ksort($expected, SORT_STRING);

        Assert::assertSame($expected, $asked($tenants), 'Each tenant must answer every tenant its answer depends on, from itself to the one whose rule applies.');
        $inside = DB::connection(StorageConnection::name())->transaction(static fn (): array => $asked(array_reverse($tenants)));

        Assert::assertSame($expected, $inside, 'Inside the transaction each tenant must answer the same.');
    }

    /**
     * Each tenant asks only about tenants on its path, and lets what the
     * question throws propagate.
     *
     * @return void
     */
    public function testEnforcementInheritanceAsksOnlyOfItsPath(): void
    {
        foreach (array_keys($this->inheritancePaths()) as $tenant) {

            $tenant   = (string) $tenant;
            $askedFor = [];
            $path     = $this->enforcementInheritance()->enforcementPath($tenant, $this->inheritanceApplication(), static function (string $tenantId) use (&$askedFor): bool {
                $askedFor[] = $tenantId;

                return (new EnforcementFinder)->find($tenantId) !== null;
            });

            Assert::assertSame([], array_values(array_diff($askedFor, $path)), "[{$tenant}] must ask only about tenants on the path it answers.");

            $refusal = EnforcementPathChanged::retryWhole();
            $called  = false;

            try {
                $this->enforcementInheritance()->enforcementPath($tenant, $this->inheritanceApplication(), static function () use (&$called, $refusal): bool {
                    $called = true;

                    throw $refusal;
                });

                Assert::assertFalse($called, "[{$tenant}] must let what the question throws propagate.");
            } catch (\Throwable $exception) {
                Assert::assertSame($refusal, $exception, "[{$tenant}] must let what the question throws propagate.");
            }
        }
    }

    /**
     * The binding under test.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\EnforcementInheritance
     */
    abstract protected function enforcementInheritance(): EnforcementInheritance;

    /**
     * The application asked about.
     *
     * @return string
     */
    abstract protected function inheritanceApplication(): string;

    /**
     * Tenants set up for the test, with their rules stored, each with its path:
     * at least one with a rule of its own and one that inherits.
     *
     * @return array<string, non-empty-list<string>>
     */
    abstract protected function inheritancePaths(): array;
}
