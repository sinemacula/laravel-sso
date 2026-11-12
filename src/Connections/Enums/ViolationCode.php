<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections\Enums;

/**
 * Why a setting was refused, generic enough for any protocol driver to use.
 *
 * Values are stable once released: never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ViolationCode: string
{
    // A setting the protocol or the operation needs is missing or empty
    case REQUIRED = 'required';

    // The setting has the wrong type
    case INVALID_TYPE = 'invalid_type';

    // The value is malformed for its kind
    case INVALID_FORMAT = 'invalid_format';

    // A URL that must be `https` is not
    case NOT_HTTPS = 'not_https';

    // The value is longer than its cap
    case TOO_LONG = 'too_long';

    // The list or map has more entries than its cap
    case TOO_MANY = 'too_many';

    // The value is outside the setting's allow-list
    case NOT_ALLOWED = 'not_allowed';

    // The value would set something the package controls
    case RESERVED = 'reserved';

    // The setting is not one the protocol has
    case UNKNOWN = 'unknown';

    // The value appears twice where it must appear once
    case DUPLICATE = 'duplicate';

    // The setting, such as tenant or protocol, is fixed at creation
    case IMMUTABLE = 'immutable';

    // A PEM that must hold a certificate or a public key holds a private key
    case PRIVATE_KEY_REFUSED = 'private_key_refused';

    // An RSA modulus under 2048 bits or an unsupported elliptic curve
    case WEAK_KEY = 'weak_key';

    // The scopes leave out `openid`
    case OPENID_SCOPE_REQUIRED = 'openid_scope_required';

    // The setting needs another setting, feature or key type that is missing
    case UNSUPPORTED = 'unsupported';
}
