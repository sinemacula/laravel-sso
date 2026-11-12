<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Applications\Enums;

/**
 * Where a completion puts the handoff code on the redirect URI.
 *
 * The fragment never reaches a server or a `Referer` header; the query string
 * is for clients that cannot read a fragment.
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
