<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Saml2\Library;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\ElementRegistries;

/**
 * Unit tests for where the XML library loads its element registries from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ElementRegistries::class)]
final class ElementRegistriesTest extends TestCase
{
    /**
     * The directory is the installer plugin's, below the project root.
     *
     * @return void
     */
    public function testTheDirectoryIsTheInstallerPluginsClasses(): void
    {
        $directory = ElementRegistries::directory();

        self::assertSame(dirname(__DIR__, 5) . '/vendor/simplesamlphp/composer-xmlprovider-installer/classes', $directory);
        self::assertDirectoryExists($directory);
    }
}
