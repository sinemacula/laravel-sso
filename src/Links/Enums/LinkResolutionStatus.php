<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links\Enums;

/**
 * What resolving a verified result's link came to (SSO-8.2, SSO-8.3, SSO-8.8):
 * linked to an identity; absent, the only answer that lets a result be offered
 * for provisioning, reserve a link or take an unlinked handoff; held by another
 * flow's live reservation; a link suspended until a confirming `link`; or a
 * link of verified domain provenance whose identity's principals could not be
 * judged, which refuses that attempt and changes nothing.
 *
 * Backed, and stable once released: a value is never renamed or reused.
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

    // A link holds the subject, and `Contracts\PrincipalScope` answered
    // `unknown` for its identity: this attempt is refused, and nothing is
    // suspended
    case SCOPE_UNKNOWN = 'scope_unknown';
}
