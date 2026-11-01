<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Enums;

/**
 * What a protocol driver found a response correlated with, before anything in
 * it is validated (SSO-5.1, SSO-5.8): an authorisation request the package
 * stored, by the OIDC `state`, or the SAML `RelayState` and `InResponseTo`; no
 * request at all, for an unsolicited SAML response (no `InResponseTo` on the
 * response or any bearer confirmation); or nothing it can read, which leaves no
 * trusted redirect target.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum CorrelationKind: string
{
    // The response names an authorisation request
    case SOLICITED = 'solicited';

    // An unsolicited SAML response, which only re-initiation may answer
    case UNSOLICITED = 'unsolicited';

    // Nothing in the response correlates it with a request
    case UNCORRELATED = 'uncorrelated';
}
