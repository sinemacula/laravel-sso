<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Revocation\Enums;

/**
 * Which sessions a revocation concerns.
 *
 * Values are stable; never rename or reuse one.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RevocationScopeKind: string
{
    // The tenant's sessions its current enforcement no longer allows
    case TENANT = 'tenant';

    // Every session established through the connection
    case CONNECTION = 'connection';

    // The identity's sessions established through the connection
    case IDENTITY_CONNECTION = 'identity_connection';

    // The identity's sessions established through the link
    case IDENTITY_LINK = 'identity_link';
}
