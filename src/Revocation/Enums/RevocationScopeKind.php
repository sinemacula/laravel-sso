<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Revocation\Enums;

/**
 * Which sessions a call to the `Contracts\SessionRevocation` contract concerns
 * (SSO-4.5): those active in a tenant that no longer comply with its
 * enforcement, those established through a connection, or one identity's
 * established through a connection.
 *
 * Backed, and stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RevocationScopeKind: string
{
    // The sessions active in the tenant that its enforcement, as it now is, no
    // longer allows
    case TENANT = 'tenant';

    // Every session established through the connection
    case CONNECTION = 'connection';

    // The identity's sessions established through the connection
    case IDENTITY_CONNECTION = 'identity_connection';
}
