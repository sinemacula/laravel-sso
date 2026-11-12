<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Revocation\Enums;

/**
 * Why sessions are revoked, for an adapter to record against each one.
 *
 * Values are stable; never rename or reuse one.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RevocationReason: string
{
    // A tenant's enforcement was turned on, or its connections changed
    case ENFORCEMENT_CHANGED = 'enforcement_changed';

    // The connection the sessions were established through was disabled
    case CONNECTION_DISABLED = 'connection_disabled';

    // The connection the sessions were established through was deleted
    case CONNECTION_DELETED = 'connection_deleted';

    // The identity's link through the connection was removed
    case LINK_REMOVED = 'link_removed';

    // The identity gained a principal outside the tenant; its domain link is
    // suspended
    case SCOPE_WIDENED = 'scope_widened';
}
