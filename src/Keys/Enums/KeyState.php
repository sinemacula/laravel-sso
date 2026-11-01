<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys\Enums;

/**
 * Where one of the service provider's own key pairs is in its rotation
 * (SSO-2.7): added and published as `next`, made `current`, then `retiring` for
 * the configured overlap, during which decryption still accepts it, until it is
 * retired and removed. A trusted identity provider certificate has no state:
 * each is trusted until it is removed.
 *
 * At most one key of a use is `current` and at most one `next` for a connection
 * at any time.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum KeyState: string
{
    // Added and published alongside the current key (SSO-5.9), not yet used
    case NEXT = 'next';

    // The key signing and, for encryption, published and decrypting
    case CURRENT = 'current';

    // Replaced by a newer current key; decryption still accepts it until its
    // overlap ends
    case RETIRING = 'retiring';
}
