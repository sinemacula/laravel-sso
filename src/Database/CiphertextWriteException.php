<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Database;

/**
 * A failed ciphertext write; names only the SQLSTATE and chains nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class CiphertextWriteException extends \RuntimeException {}
