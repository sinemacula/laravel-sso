<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains\Enums;

/**
 * Where a connection's claim of a domain stands.
 *
 * Linking needs more than `verified`: see `DomainStanding::allowsLinking()`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum DomainState: string
{
    // Claimed, with a token, and waiting for its record until the claim expires
    case PENDING = 'pending';

    // Its record carried the token; verified for this connection and no other
    case VERIFIED = 'verified';

    // Its record was missing or changed for longer than the grace period
    case LAPSED = 'lapsed';
}
