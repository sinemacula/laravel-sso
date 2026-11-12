<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Logging;

/**
 * A KMS refusal, whose message may name the call's credentials.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KmsException extends \RuntimeException {}
