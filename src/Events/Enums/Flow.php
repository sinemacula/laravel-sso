<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events\Enums;

/**
 * The operation a `FlowFailed` event reports a refusal of.
 *
 * Stable once released: a case is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Flow: string
{
    // Starting a flow, discovery by email domain included
    case AUTHORIZATION_REQUEST = 'authorization_request';

    // A SAML response, solicited or unsolicited
    case ASSERTION = 'assertion';

    // An OIDC authorisation response at the callback
    case CALLBACK = 'callback';

    // A handoff code presented for redemption
    case REDEMPTION = 'redemption';
}
