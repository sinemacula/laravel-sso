<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Exceptions;

/**
 * Thrown by the configuration check when the XML library would not load an XML
 * provider package's element registry exactly once, naming the package.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ElementRegistryException extends \RuntimeException {}
