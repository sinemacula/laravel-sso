<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Applications\Enums;

/**
 * Where a completion puts the handoff code and the request's public reference
 * on an application's redirect URI (SSO-5.6, SSO-5.7): in the fragment, which
 * never reaches a server or a `Referer` header, or in the query string, for an
 * application whose client cannot read a fragment. The value is the setting
 * `sso.applications.<name>.delivery` holds.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum HandoffDelivery: string
{
    // In the URL fragment; the default
    case FRAGMENT = 'fragment';

    // In the query string
    case QUERY = 'query';
}
