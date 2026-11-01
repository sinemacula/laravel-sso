<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\TestCase;

/**
 * Feature tests for the package SsoServiceProvider.
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
     * The package's configuration is merged under the `sso` key, with the
     * package's defaults.
     *
     * @return void
     */
    public function testThePackageConfigurationIsMergedUnderTheSsoKey(): void
    {
        $config = $this->app?->make(ConfigRepository::class);

        self::assertInstanceOf(ConfigRepository::class, $config);
        self::assertTrue($config->has('sso'));
        self::assertSame(require dirname(__DIR__, 2) . '/config/sso.php', $config->get('sso'));
    }

    /**
     * A value the application sets in its own `sso` configuration takes
     * precedence over the package's default.
     *
     * @return void
     */
    public function testTheApplicationsConfigurationTakesPrecedence(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app    = $this->app;
        $config = $app->make(ConfigRepository::class);

        $config->set('sso', ['application' => 'value']);

        (new SsoServiceProvider($app))->register();

        self::assertSame('value', $config->get('sso.application'));
    }

    /**
     * The `sso-config` publish group is registered with the framework's publish
     * registry.
     *
     * @return void
     */
    public function testConfigPublishingTagIsRegistered(): void
    {
        self::assertContains('sso-config', ServiceProvider::publishableGroups());
    }

    /**
     * The config tag publishes the package's config file to the application's
     * `config/sso.php`.
     *
     * @return void
     */
    public function testConfigPublishingTagPublishesThePackageConfig(): void
    {
        $paths = [];

        foreach (ServiceProvider::pathsToPublish(SsoServiceProvider::class, 'sso-config') as $from => $to) {
            $paths[(string) realpath($from)] = $to;
        }

        self::assertSame([
            realpath(dirname(__DIR__, 2) . '/config/sso.php') => config_path('sso.php'),
        ], $paths);
    }

    /**
     * Booting outside the console registers no publish path, checked against an
     * emptied registry so the paths the test application's boot registered
     * cannot hide one.
     *
     * @return void
     */
    public function testNothingIsPublishedOutsideTheConsole(): void
    {
        $app = \Mockery::mock(Application::class)->makePartial();
        $app->shouldReceive('runningInConsole')->andReturnFalse();

        [$publishes, $groups] = [ServiceProvider::$publishes, ServiceProvider::$publishGroups];

        ServiceProvider::$publishes     = [];
        ServiceProvider::$publishGroups = [];

        try {
            (new SsoServiceProvider($app))->boot();

            self::assertSame([], ServiceProvider::$publishes);
            self::assertSame([], ServiceProvider::$publishGroups);
        } finally {
            [ServiceProvider::$publishes, ServiceProvider::$publishGroups] = [$publishes, $groups];
        }
    }
}
