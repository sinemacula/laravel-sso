<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Database;

/**
 * A table a shipped migration creates already exists.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class TableAlreadyExistsException extends \RuntimeException {}
