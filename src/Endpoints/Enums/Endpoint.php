<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Endpoints\Enums;

/**
 * An endpoint the package publishes for each connection whose path pattern is
 * configured (SSO-5.5). The value is the pattern's key under
 * `sso.endpoints.paths`. The service provider entity id is not one: the default
 * resolver makes it the metadata URL.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Endpoint: string
{
    // The SAML assertion consumer service, which accepts HTTP-POST only
    // (SSO-5.3)
    case ASSERTION_CONSUMER_SERVICE = 'assertion_consumer_service';

    // The OIDC callback, sent as `redirect_uri` (SSO-5.4)
    case CALLBACK = 'callback';

    // The service provider metadata, and the default entity id (SSO-5.9)
    case METADATA = 'metadata';
}
