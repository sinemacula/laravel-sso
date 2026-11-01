<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events\Enums;

/**
 * The operation a `FlowFailed` event reports a refusal of (SSO-10.2): each
 * refused authorisation request, SAML response, OIDC callback and handoff
 * redemption fires one failure event naming its flow and its reason.
 *
 * Backed, so a listener counts refusals by flow without reading the event's
 * class, and stable once released: a case is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Flow: string
{
    // Starting a flow: an authorisation request for a connection, discovery by
    // email domain included (SSO-5.1, SSO-3.4)
    case AUTHORIZATION_REQUEST = 'authorization_request';

    // A SAML response at the assertion consumer service, solicited or
    // unsolicited (SSO-6, SSO-5.8)
    case ASSERTION = 'assertion';

    // An OIDC authorisation response at the callback (SSO-7)
    case CALLBACK = 'callback';

    // A handoff code presented for redemption (SSO-9.2, SSO-9.9)
    case REDEMPTION = 'redemption';
}
