<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Enums;

/**
 * How a completion at an assertion consumer service or a callback ended
 * (SSO-5.6, SSO-5.7, SSO-5.8, SSO-11.8): completed, with a handoff code for
 * the application's redirect URI; failed, with a code for that same URI;
 * rejected, with no trusted redirect target to send the browser to; rate
 * limited, with the seconds until it may be tried again; or re-initiated, an
 * unsolicited SAML response answered with the connection's start URL.
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
