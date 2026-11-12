<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Endpoints\Enums;

/**
 * A per-connection endpoint; the value is its key under `sso.endpoints.paths`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Endpoint: string
{
    // The SAML assertion consumer service, which accepts HTTP-POST only
    case ASSERTION_CONSUMER_SERVICE = 'assertion_consumer_service';

    // The OIDC callback, sent as `redirect_uri`
    case CALLBACK = 'callback';

    // The service provider metadata, and the default entity id
    case METADATA = 'metadata';

    // The OIDC client assertion keys, fetched as the client's `jwks_uri`
    case JWKS = 'jwks';
}
