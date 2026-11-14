<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Seams\Concerns;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Database\StorageConnection;

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
     * Each tenant answers its enforcing tenant byte for byte, asked in turn,
     * then again in reverse inside a transaction on the storage connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEnforcementInheritanceAnswersEachTenantsEnforcingTenant(): void
    {
        $inheritance = $this->enforcementInheritance();
        $application = $this->inheritanceApplication();
        $expected    = $this->enforcingTenants();
        $asked       = static function (array $tenants) use ($inheritance, $application): array {

            $answers = [];

            foreach ($tenants as $tenant) {
                $answers[$tenant] = $inheritance->enforcingTenant((string) $tenant, $application);
            }

            ksort($answers, SORT_STRING);

            return $answers;
        };

        $tenants = array_keys($expected);

        ksort($expected, SORT_STRING);

        Assert::assertSame($expected, $asked($tenants), 'Each tenant must answer the tenant whose rule applies to it, exactly.');
        $inside = DB::connection(StorageConnection::name())->transaction(static fn (): array => $asked(array_reverse($tenants)));

        Assert::assertSame($expected, $inside, 'Inside the transaction each tenant must answer the same.');
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
     * Tenants set up for the test, each with the tenant whose rule applies to
     * it: at least one with a rule of its own and one that inherits.
     *
     * @return array<string, string>
     */
    abstract protected function enforcingTenants(): array;
}
