<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Logging;

/**
 * What the example application's key management service client throws when the
 * service refuses a call (SSO-2.5): its message, as a cloud provider's SDK
 * writes one, may name the credentials the call carried.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KmsException extends \RuntimeException {}
