<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\TestCase;

/**
 * Integration tests for publishing the package's configuration through
 * `vendor:publish`, as an application installing the package does.
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
     * Publishing the `sso-config` tag writes the package's configuration to the
     * application's `config/sso.php`, unchanged.
     *
     * @return void
     */
    public function testPublishingTheConfigTagWritesThePackageConfiguration(): void
    {
        $published = config_path('sso.php');

        self::assertFileDoesNotExist($published);

        try {
            self::assertSame(0, Artisan::call('vendor:publish', ['--tag' => 'sso-config']));

            self::assertFileEquals(dirname(__DIR__, 2) . '/config/sso.php', $published);
        } finally {
            if (is_file($published)) {
                unlink($published);
            }
        }
    }
}
