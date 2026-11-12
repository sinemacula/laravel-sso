<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Enums;

/**
 * What a protocol driver found a response correlated with, before validation.
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
