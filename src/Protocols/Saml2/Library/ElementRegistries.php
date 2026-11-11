<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use SimpleSAML\XML\Registry\ElementRegistry;

/**
 * Where the XML library loads its element registries from: the directory its
 * `ElementRegistry` derives from its own file, which the Composer plugin
 * `simplesamlphp/composer-xmlprovider-installer` fills with each XML provider
 * package's registry. A registry missing from it leaves the library unable to
 * parse that package's elements.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ElementRegistries
{
    /** @var string The directory, below the project root `ElementRegistry` takes to be seven levels above its file. */
    private const string DIRECTORY = '/vendor/simplesamlphp/composer-xmlprovider-installer/classes';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The directory `ElementRegistry` loads every `element.registry.*.php` file
     * from.
     *
     * @return string
     */
    public static function directory(): string
    {
        return dirname((new \ReflectionClass(ElementRegistry::class))->getFileName() ?: '', 7) . self::DIRECTORY;
    }
}
