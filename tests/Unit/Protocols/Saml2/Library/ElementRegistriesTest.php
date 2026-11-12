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

    /**
     * `ElementRegistries` is a utility container, not to be instantiated.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ElementRegistries::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ElementRegistries::class, $instance);
    }
}
