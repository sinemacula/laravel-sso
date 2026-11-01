<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Results\Enums;

/**
 * Where the linking email of a verified result came from (SSO-8.1, SSO-8.8):
 * the validated ID token, a validated UserInfo response whose `sub` matched it,
 * or the one SAML attribute the connection names by exact `Name` and
 * `NameFormat`. Never from attribute mapping.
 *
 * Backed, and stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum LinkingEmailSource: string
{
    // The `email` claim of the validated ID token, with `email_verified` true
    case ID_TOKEN = 'id_token';

    // The `email` claim of a validated UserInfo response, with `email_verified`
    // true
    case USERINFO = 'userinfo';

    // The SAML attribute the connection names
    case SAML_ATTRIBUTE = 'saml_attribute';
}
