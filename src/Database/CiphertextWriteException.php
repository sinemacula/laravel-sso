<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Database;

/**
 * Thrown when a write that carries a ciphertext fails; its message names the
 * failure and the SQLSTATE only, and it chains nothing, so no part of the
 * ciphertext reaches a log or an error report.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class CiphertextWriteException extends \RuntimeException {}
