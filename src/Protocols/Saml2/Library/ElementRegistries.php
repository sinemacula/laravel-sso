<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use SimpleSAML\XML\Registry\ElementRegistry;

/**
 * Where the XML library loads its element registries from, as filled by the
 * `simplesamlphp/composer-xmlprovider-installer` Composer plugin.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ElementRegistries
{
    /** @var string Below the root `ElementRegistry` takes as seven levels up. */
    private const string DIRECTORY = '/vendor/simplesamlphp/composer-xmlprovider-installer/classes';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The directory `ElementRegistry` loads `element.registry.*.php` from.
     *
     * @return string
     */
    public static function directory(): string
    {
        return dirname((new \ReflectionClass(ElementRegistry::class))->getFileName() ?: '', 7) . self::DIRECTORY;
    }
}
