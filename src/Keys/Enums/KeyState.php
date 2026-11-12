<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys\Enums;

/**
 * Where one of the service provider's own key pairs is in its rotation.
 *
 * A connection has at most one `current` and one `next` key of each use.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum KeyState: string
{
    // Published alongside the current key, not yet used
    case NEXT = 'next';

    // The key signing and, for encryption, published and decrypting
    case CURRENT = 'current';

    // Replaced; decryption still accepts it until its overlap ends
    case RETIRING = 'retiring';
}
