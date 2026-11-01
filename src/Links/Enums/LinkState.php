<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links\Enums;

/**
 * Where a stored link stands (SSO-8.4, SSO-8.8): active, resolving its issuer
 * and subject to its identity; or reserved by a completion that matched the
 * subject to an identity by a verified domain, holding the link's place under
 * the store's uniqueness and the link limit until its handoff is redeemed, its
 * reservation expires or it is voided. A reserved link resolves nothing.
 *
 * Backed, and stable once released: a value is never renamed or reused.
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

    // The link is held for a redemption that may activate it, and resolves
    // nothing (SSO-8.8)
    case RESERVED = 'reserved';
}
