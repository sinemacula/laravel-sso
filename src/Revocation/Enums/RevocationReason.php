<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Revocation\Enums;

/**
 * Why the package asks for sessions to be revoked (SSO-4.5), passed to the
 * `Contracts\SessionRevocation` contract with the scope, so an adapter can
 * record it against each session it revokes.
 *
 * Backed, and stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RevocationReason: string
{
    // A tenant's enforcement was turned on, or the connections that satisfy it
    // changed
    case ENFORCEMENT_CHANGED = 'enforcement_changed';

    // The connection the sessions were established through was disabled
    case CONNECTION_DISABLED = 'connection_disabled';

    // The connection the sessions were established through was deleted
    case CONNECTION_DELETED = 'connection_deleted';

    // The identity's link through the connection was removed
    case LINK_REMOVED = 'link_removed';
}
