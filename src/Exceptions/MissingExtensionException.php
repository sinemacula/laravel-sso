<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Exceptions;

/**
 * Thrown by the configuration check when a PHP extension, or a function the
 * package needs from one or its polyfill, is not available, naming it and what
 * the package needs it for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class MissingExtensionException extends \RuntimeException {}
