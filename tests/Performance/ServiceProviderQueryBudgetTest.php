<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\TestCase;

/**
 * Query budget for registering and booting the package: no query at all.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoServiceProvider::class)]
final class ServiceProviderQueryBudgetTest extends TestCase
{
    /**
     * Registering and booting the provider issues no query.
     *
     * @return void
     */
    public function testRegisteringAndBootingThePackageIssuesNoQuery(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app     = $this->app;
        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        self::assertFalse($app->providerIsLoaded(SsoServiceProvider::class));

        $app->register(SsoServiceProvider::class);

        self::assertTrue($app->providerIsLoaded(SsoServiceProvider::class));
        self::assertSame([], $queries);
    }

    /**
     * Leave the provider out, so the test registers and boots it first.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [];
    }
}
