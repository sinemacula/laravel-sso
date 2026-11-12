<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

/**
 * Scoped marker that tells `ProtocolManager` a request or job scope has ended,
 * so drivers holding scoped services are rebuilt.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DriverScope {}
