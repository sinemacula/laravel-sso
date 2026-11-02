<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Enums;

/**
 * How the key for an ID token's signature was looked for in the connection's
 * stored JWKS (SSO-7.3).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum KeySelectionOutcome: string
{
    // Exactly one stored key is the token's: the one whose own `kid` is the
    // header's, or, with no header `kid`, the only key admissible for its
    // algorithm
    case FOUND = 'found';

    // No stored key has the header's `kid`, or none is admissible for a token
    // without one: the JWKS may be refetched once, within the cooldown
    case UNKNOWN = 'unknown';

    // The token's algorithm is not allowed, the key with its `kid` does not fit
    // the algorithm, or a token without a `kid` matches more than one key:
    // refused, with no refetch
    case REFUSED = 'refused';

    // A trust change overtook the refetch for this token and no stored key is
    // its key: the connection, not the token, is what refuses it
    case OVERTAKEN = 'overtaken';
}
