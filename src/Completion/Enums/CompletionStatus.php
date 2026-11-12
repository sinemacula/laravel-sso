<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Enums;

/**
 * How a completion ended.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum CompletionStatus: string
{
    // A handoff code was issued; the browser goes to the redirect URI with it
    case COMPLETED = 'completed';

    // The flow failed; the browser goes to the redirect URI with the code
    case FAILED = 'failed';

    // No trusted redirect target is known; answered with a 400
    case REJECTED = 'rejected';

    // A limit is full; answered with a 429 and `Retry-After`
    case RATE_LIMITED = 'rate_limited';

    // An unsolicited SAML response; the browser goes to the start URL
    case REINITIATED = 'reinitiated';
}
