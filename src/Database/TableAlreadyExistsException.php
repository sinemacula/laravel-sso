<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Database;

/**
 * Thrown when a table a shipped migration creates already exists in the
 * consumer's schema before the migration runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class TableAlreadyExistsException extends \RuntimeException {}
