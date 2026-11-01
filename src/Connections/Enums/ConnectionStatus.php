<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections\Enums;

/**
 * How a management helper's change to a connection ended (SSO-2.11): the
 * `status` of a `Connections\ConnectionResult`. Seven are successes (the
 * connection created, updated, left unchanged, enabled, disabled, deleted or
 * migrated) and two are refusals, each of which changed nothing: `refused`,
 * with a `FailureReason`, and `invalid`, with the settings refused.
 *
 * Backed, and stable once released: a value is never renamed or reused.
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

    // The change gave what the connection already held, or enabled an enabled
    // connection; nothing was written or reported
    case UNCHANGED = 'unchanged';

    // The connection was enabled
    case ENABLED = 'enabled';

    // The connection was disabled: what was in flight voided, its sessions
    // revoked
    case DISABLED = 'disabled';

    // The connection was deleted with every row it owned, its sessions revoked
    case DELETED = 'deleted';

    // A subject migration changed the connection and relinked or removed its
    // links
    case MIGRATED = 'migrated';

    // The change was refused: the caller's authentication is not fresh enough,
    // the tenant has no such connection, or its protocol is unavailable
    case REFUSED = 'refused';

    // A setting, a secret, the display name or the attribute mapping was
    // refused; the result carries the violations
    case INVALID = 'invalid';
}
