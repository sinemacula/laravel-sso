<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

/**
 * The objects and arrays open at one point of a JSON text, the innermost on
 * top, each with the member names seen in it so far, as `StrictJson` reads the
 * text for a name given twice.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @extends \SplStack<\ArrayObject<string, string>>
 *
 * @internal
 */
final class OpenContainers extends \SplStack {}
