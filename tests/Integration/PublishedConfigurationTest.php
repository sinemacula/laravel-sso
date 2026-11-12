<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\ServiceProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\TestCase;

/**
 * Integration tests for publishing the package configuration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoServiceProvider::class)]
final class PublishedConfigurationTest extends TestCase
{
    /**
     * Publishing `sso-config` writes `config/sso.php` unchanged. The config
     * directory is moved to the test's own, since parallel workers share it.
     *
     * @return void
     */
    public function testPublishingTheConfigTagWritesThePackageConfiguration(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app        = $this->app;
        $configPath = $app->configPath();
        $directory  = sys_get_temp_dir() . '/' . uniqid('laravel-sso-', true);
        $published  = $directory . '/sso.php';

        [$publishes, $groups] = [ServiceProvider::$publishes, ServiceProvider::$publishGroups];

        mkdir($directory);

        try {
            $app->useConfigPath($directory);

            (new SsoServiceProvider($app))->boot();

            self::assertSame(0, Artisan::call('vendor:publish', ['--tag' => 'sso-config']));

            self::assertFileEquals(dirname(__DIR__, 2) . '/config/sso.php', $published);
        } finally {
            [ServiceProvider::$publishes, ServiceProvider::$publishGroups] = [$publishes, $groups];

            $app->useConfigPath($configPath);

            if (is_file($published)) {
                unlink($published);
            }

            rmdir($directory);
        }
    }
}
