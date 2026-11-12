<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Enums;

/**
 * The result of looking up an ID token's signing key in the stored JWKS.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum KeySelectionOutcome: string
{
    // Exactly one stored key matches the header `kid`, or the algorithm when
    // there is no `kid`
    case FOUND = 'found';

    // No stored key matches; the JWKS may be refetched once within the cooldown
    case UNKNOWN = 'unknown';

    // Disallowed algorithm, mismatched key or ambiguous match; no refetch
    case REFUSED = 'refused';

    // A trust change overtook the refetch and no stored key matches
    case OVERTAKEN = 'overtaken';
}
