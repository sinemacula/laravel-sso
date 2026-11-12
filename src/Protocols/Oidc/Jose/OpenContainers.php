<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

/**
 * The JSON containers open while `StrictJson` scans for duplicate member names,
 * innermost on top, each with the names seen so far.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @extends \SplStack<\ArrayObject<string, string>>
 *
 * @internal
 */
final class OpenContainers extends \SplStack {}
