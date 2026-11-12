<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections\Enums;

/**
 * How a management helper's change to a connection ended.
 *
 * Values are stable once released: never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ConnectionStatus: string
{
    // The connection was created, disabled
    case CREATED = 'created';

    // The connection's settings, secrets, name or mapping changed
    case UPDATED = 'updated';

    // The change matched what the connection held; nothing was written
    case UNCHANGED = 'unchanged';

    // The connection was enabled
    case ENABLED = 'enabled';

    // The connection was disabled, in-flight work voided and sessions revoked
    case DISABLED = 'disabled';

    // The connection was deleted with every row it owned, its sessions revoked
    case DELETED = 'deleted';

    // A subject migration relinked or removed the connection's links
    case MIGRATED = 'migrated';

    // The change was refused with a reason; nothing changed
    case REFUSED = 'refused';

    // The input was refused; the result carries the violations
    case INVALID = 'invalid';
}
