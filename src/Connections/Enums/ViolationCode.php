<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections\Enums;

/**
 * Why a setting given to a management helper was refused (SSO-2.11): the
 * machine-readable code of one `Connections\SettingViolation`, which names the
 * setting it applies to. The application words it (SSO-12.6).
 *
 * The codes are generic, so a protocol driver an application registers judges
 * its own settings with the same vocabulary; the setting the violation names
 * says which value it was. Backed, and stable once released: a value is never
 * renamed or reused, and a removed one leaves its value unused.
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

    // The setting has the wrong type: a string where a list was expected, say
    case INVALID_TYPE = 'invalid_type';

    // The value is malformed: not a URL, an entity id, a name or a PEM block of
    // the kind expected
    case INVALID_FORMAT = 'invalid_format';

    // A URL that must be `https` is not
    case NOT_HTTPS = 'not_https';

    // The value is longer than its cap
    case TOO_LONG = 'too_long';

    // The list or map has more entries than its cap
    case TOO_MANY = 'too_many';

    // The value is outside the setting's allow-list: an algorithm, a binding, a
    // client authentication method, an authorisation parameter, a key type
    case NOT_ALLOWED = 'not_allowed';

    // The value would set something the package reserves: a parameter the flow
    // controls (SSO-2.4), a field of the verified result or a protocol value as
    // a mapping target or source (SSO-2.10)
    case RESERVED = 'reserved';

    // The setting is not one the protocol has
    case UNKNOWN = 'unknown';

    // The value appears twice where it must appear once: a certificate already
    // trusted, a mapping source named twice
    case DUPLICATE = 'duplicate';

    // The setting cannot change once the connection exists: its tenant and its
    // protocol (SSO-2.1)
    case IMMUTABLE = 'immutable';

    // A PEM that must hold a certificate or a public key holds a private key
    case PRIVATE_KEY_REFUSED = 'private_key_refused';

    // The key is weaker than the package accepts: an RSA modulus under 2048
    // bits, or an elliptic curve it does not support
    case WEAK_KEY = 'weak_key';

    // The scopes leave out `openid` (SSO-2.4)
    case OPENID_SCOPE_REQUIRED = 'openid_scope_required';

    // The setting needs another that is not set or not on: a client
    // authentication of `private_key_jwt` with no key, an IdP-initiated start
    // URL with IdP-initiated sign-in off, a feature switched off in
    // `sso.features`
    case UNSUPPORTED = 'unsupported';
}
