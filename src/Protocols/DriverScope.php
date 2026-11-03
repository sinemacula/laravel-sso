<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

/**
 * Marks one scope of the application for `ProtocolManager`, as nothing else
 * says when a scope has ended: bound as scoped, its instance is forgotten after
 * every request and job with the services a driver holds, so another instance
 * means those drivers hold what has been forgotten. It holds nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DriverScope {}
