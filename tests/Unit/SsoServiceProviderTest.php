<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * Unit tests for the package SsoServiceProvider, on a bare application with no
 * framework bootstrapping.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoServiceProvider::class)]
final class SsoServiceProviderTest extends TestCase
{
    /**
     * Registering the provider merges the package's configuration under the
     * `sso` key and binds nothing else.
     *
     * @return void
     */
    public function testRegisteringMergesThePackageConfigurationOnly(): void
    {
        $app    = new Application(dirname(__DIR__, 2));
        $config = new ConfigRepository;

        $app->instance('config', $config);

        $bindings = $app->getBindings();

        (new SsoServiceProvider($app))->register();

        self::assertSame(['sso' => require dirname(__DIR__, 2) . '/config/sso.php'], $config->all());
        self::assertSame($bindings, $app->getBindings());
    }
}
