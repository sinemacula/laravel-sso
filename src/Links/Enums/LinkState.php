<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links\Enums;

/**
 * Where a stored link stands.
 *
 * A reserved or suspended link resolves nothing, yet still holds the subject
 * against provisioning and new reservations.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum LinkState: string
{
    // The link resolves its issuer and subject to its identity
    case ACTIVE = 'active';

    // Held for the redemption that may activate it
    case RESERVED = 'reserved';

    // A domain-made link suspended until a confirming `link` flow
    case SUSPENDED = 'suspended';
}
