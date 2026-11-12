<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Results\Enums;

/**
 * Where a verified result's linking email came from; never attribute mapping.
 *
 * Stable once released: a value is never renamed or reused.
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

    // The `email` claim of a validated UserInfo response whose `sub` matched
    case USERINFO = 'userinfo';

    // The SAML attribute the connection names by exact `Name` and `NameFormat`
    case SAML_ATTRIBUTE = 'saml_attribute';
}
