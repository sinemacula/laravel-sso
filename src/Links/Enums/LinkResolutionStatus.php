<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links\Enums;

/**
 * What resolving a verified result's link came to.
 *
 * Only `absent` lets a result be provisioned, reserve a link or take an
 * unlinked handoff.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum LinkResolutionStatus: string
{
    // An active link resolves the subject to its identity
    case LINKED = 'linked';

    // No link holds the subject; an expired reservation is logically absent
    case ABSENT = 'absent';

    // A live reservation holds the subject, and resolves no sign-in
    case RESERVED = 'reserved';

    // A link holds the subject, suspended, and resolves nothing
    case SUSPENDED = 'suspended';

    // `Contracts\PrincipalScope` answered `unknown`; refused, nothing suspended
    case SCOPE_UNKNOWN = 'scope_unknown';
}
